#!/usr/bin/env python3
"""CVEX v3 runner for CS279 A02.

Usage:
    python3 .cs279/cvex.py check CVE-YYYY-NNNNN
    python3 .cs279/cvex.py run CVE-YYYY-NNNNN --fresh-flag --out /tmp/run1
    python3 .cs279/cvex.py verify CVE-YYYY-NNNNN

The runner is intentionally record-driven, but it does not execute a record's
compose.yml.  The runner builds the four standard role images itself and only
passes the planted flag to the target container.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
FLAG_RE = re.compile(r"CVEX\{[0-9a-fA-F]{32}\}")
FLAG_LINE_RE = re.compile(r"CVEX_FLAG=(CVEX\{[0-9a-fA-F]{32}\})")
ROLE_DIRS = ("target", "benign", "attacker", "recorder")
# A JVM target traces hundreds of megabytes of syscalls in a minute. GitHub
# refuses any file over 100 MB and the course does not support Git LFS, so a
# committed dataset has to stay well under that: the trace is truncated here,
# and the cut is recorded in the file itself rather than passing unnoticed.
SYSCALL_MAX_BYTES = int(os.environ.get("CVEX_SYSCALL_MAX_BYTES", 48 * 1024 * 1024))
CAPS = ("NET_ADMIN", "NET_RAW", "SYS_PTRACE")


@dataclass
class CheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def need_file(self, root: Path, rel: str) -> None:
        p = root / rel
        if not p.is_file():
            self.error(f"missing file: {rel}")
        elif p.stat().st_size == 0:
            self.error(f"empty file: {rel}")

    def need_dir(self, root: Path, rel: str) -> None:
        if not (root / rel).is_dir():
            self.error(f"missing directory: {rel}")

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": self.errors, "warnings": self.warnings}


@dataclass
class CmdResult:
    code: int
    stdout: str
    stderr: str


@dataclass
class PhaseResult:
    name: str
    exit_code: int | None
    stdout: str
    stderr: str
    pcap: bool
    syscalls: bool
    ready: bool
    target_crashed: bool


class CvexError(RuntimeError):
    pass


def strip_inline_comment(text: str) -> str:
    quote = ""
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote == '"':
            escaped = True
            continue
        if ch in ("'", '"'):
            if not quote:
                quote = ch
            elif quote == ch:
                quote = ""
            continue
        if ch == "#" and not quote and (i == 0 or text[i - 1].isspace()):
            return text[:i].rstrip()
    return text.rstrip()


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in ("", "~", "null", "Null", "NULL"):
        return None
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = strip_inline_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent % 2:
            raise ValueError(f"line {lineno}: indentation must use multiples of two spaces")
        if ":" not in line:
            raise ValueError(f"line {lineno}: expected key: value")
        key, value = line.strip().split(":", 1)
        key = key.strip()
        value = value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = parse_scalar(value)
    return root


def load_manifest(path: Path) -> dict[str, Any]:
    text = path.read_text(errors="replace")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except ModuleNotFoundError:
        data = parse_simple_yaml(text)
    except Exception as e:
        raise CvexError(f"cvex.yml is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise CvexError("cvex.yml must contain a mapping at the top level")
    return data


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def run_cmd(cmd: list[str], *, cwd: Path | None = None, timeout: int | None = None,
            env: dict[str, str] | None = None) -> CmdResult:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=merged, timeout=timeout, capture_output=True,
                           text=True, errors="replace")
        return CmdResult(p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return CmdResult(124, stdout, stderr + "\n[timeout]\n")


def tail(text: str, n: int = 6000) -> str:
    return text if len(text) <= n else "[...]\n" + text[-n:]


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def resolve_record(arg: str) -> Path:
    p = Path(arg)
    if p.exists():
        return p.resolve()
    q = Path.cwd() / arg
    if q.exists():
        return q.resolve()
    raise CvexError(f"record directory not found: {arg}")


def is_text(path: Path) -> bool:
    try:
        data = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\0" not in data


def dockerfile_from_images(path: Path) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for lineno, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if not raw.lstrip().upper().startswith("FROM "):
            continue
        try:
            words = shlex.split(raw, comments=True)
        except ValueError:
            out.append((lineno, ""))
            continue
        if not words or words[0].upper() != "FROM":
            continue
        i = 1
        while i < len(words) and words[i].startswith("--"):
            i += 1
        if i < len(words):
            out.append((lineno, words[i]))
    return out


def image_pinned(image: str) -> bool:
    return image == "scratch" or "@sha256:" in image


def nested(data: dict[str, Any], *keys: str) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def check_ip(res: CheckResult, value: Any, field: str, subnet: ipaddress._BaseNetwork | None) -> None:
    if not isinstance(value, str):
        res.error(f"cvex.yml: `{field}` must be a string IP address")
        return
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        res.error(f"cvex.yml: `{field}` is not a valid IP address")
        return
    if subnet and addr not in subnet:
        res.error(f"cvex.yml: `{field}` is outside network.subnet")


def validate_manifest(record: Path, manifest: dict[str, Any], res: CheckResult) -> None:
    name = record.name
    cve = manifest.get("cve")
    if manifest.get("cvex_version") != 3:
        res.error("cvex.yml: `cvex_version` must be 3")
    if not isinstance(cve, str) or not CVE_RE.match(cve):
        res.error('cvex.yml: `cve` must look like "CVE-2023-12345"')
    elif CVE_RE.match(name) and cve != name:
        res.error(f"cvex.yml: `cve` is {cve}, but the directory is {name}")

    topology = manifest.get("topology")
    if topology not in ("single", "target-attacker", "target+db-attacker"):
        res.error('cvex.yml: `topology` must be "single", "target-attacker", or "target+db-attacker"')
    elif topology == "single":
        res.warn("A02 submissions must be remotely exploitable; `topology: single` is only for format examples")

    subnet = None
    raw_subnet = nested(manifest, "network", "subnet")
    if not isinstance(raw_subnet, str):
        res.error("cvex.yml: `network.subnet` is required")
    else:
        try:
            subnet = ipaddress.ip_network(raw_subnet, strict=False)
        except ValueError:
            res.error("cvex.yml: `network.subnet` is not valid CIDR")

    success = manifest.get("success")
    if success not in ("flag", "crash"):
        res.error('cvex.yml: `success` must be "flag" or "crash"')
    if success == "flag":
        flag = nested(manifest, "flag", "value")
        plant = nested(manifest, "flag", "plant")
        if not isinstance(flag, str) or not re.fullmatch(r"CVEX\{[0-9a-f]{32}\}", flag):
            res.error("cvex.yml: `flag.value` must be CVEX{<32 lowercase hex chars>}")
        if not isinstance(plant, str) or not plant:
            res.error("cvex.yml: `flag.plant` is required for flag records")
    elif isinstance(manifest.get("flag"), dict):
        res.warn("cvex.yml: crash records do not need a `flag` section")

    channel = nested(manifest, "capture", "flag_channel")
    if channel not in ("stdout", "network", "file"):
        res.error('cvex.yml: `capture.flag_channel` must be "stdout", "network", or "file"')
    if nested(manifest, "capture", "tls_intercept") is True:
        res.warn("TLS interception is declared, but this runner records raw packets only")
    tls_ports = nested(manifest, "capture", "tls_ports")
    if tls_ports is not None and not isinstance(tls_ports, list):
        res.error("cvex.yml: `capture.tls_ports` must be a list")

    services = manifest.get("services")
    if not isinstance(services, dict) or not isinstance(services.get("target"), dict):
        res.error("cvex.yml: `services.target` is required")
    else:
        target = services["target"]
        for key in ("image", "ip", "trace", "ready"):
            if not isinstance(target.get(key), str) or not target.get(key):
                res.error(f"cvex.yml: `services.target.{key}` is required")
        if isinstance(target.get("image"), str) and not image_pinned(target["image"]):
            res.error("cvex.yml: `services.target.image` must be pinned with @sha256")
        check_ip(res, target.get("ip"), "services.target.ip", subnet)
        ready = target.get("ready")
        if isinstance(ready, str) and not (ready.startswith("tcp:") or ready.startswith("file:") or
                                           ready.startswith("http://") or ready.startswith("https://")):
            res.error("cvex.yml: `services.target.ready` must start with tcp:, file:, http://, or https://")
        for svc_name, svc in services.items():
            if svc_name == "target":
                continue
            if not isinstance(svc, dict):
                res.error(f"cvex.yml: `services.{svc_name}` must be a mapping")
                continue
            if not isinstance(svc.get("image"), str) or not svc["image"]:
                res.error(f"cvex.yml: `services.{svc_name}.image` is required")
            elif not image_pinned(svc["image"]):
                res.error(f"cvex.yml: `services.{svc_name}.image` must be pinned with @sha256")
            if "ip" in svc:
                check_ip(res, svc.get("ip"), f"services.{svc_name}.ip", subnet)
            if not (record / svc_name / "Dockerfile").is_file():
                res.warn(f"optional service `{svc_name}` has no {svc_name}/Dockerfile; run will try the manifest image")

    phases = manifest.get("phases")
    if not isinstance(phases, dict):
        res.error("cvex.yml: `phases` is required")
    else:
        for phase in ("benign", "attack"):
            cfg = phases.get(phase)
            if not isinstance(cfg, dict):
                res.error(f"cvex.yml: `phases.{phase}` is required")
                continue
            for key in ("client", "image", "ip"):
                if not isinstance(cfg.get(key), str) or not cfg.get(key):
                    res.error(f"cvex.yml: `phases.{phase}.{key}` is required")
            if isinstance(cfg.get("image"), str) and not image_pinned(cfg["image"]):
                res.error(f"cvex.yml: `phases.{phase}.image` must be pinned with @sha256")
            check_ip(res, cfg.get("ip"), f"phases.{phase}.ip", subnet)

    wall = nested(manifest, "limits", "wall_clock_seconds")
    if not isinstance(wall, int) or not (1 <= wall <= 3600):
        res.error("cvex.yml: `limits.wall_clock_seconds` must be an integer from 1 to 3600")


def check_dockerfiles(record: Path, res: CheckResult) -> None:
    for dirname in ROLE_DIRS:
        df = record / dirname / "Dockerfile"
        if not df.is_file():
            continue
        images = dockerfile_from_images(df)
        if not images:
            res.error(f"{dirname}/Dockerfile: no FROM line found")
        for lineno, image in images:
            if not image:
                res.error(f"{dirname}/Dockerfile:{lineno}: cannot parse FROM line")
            elif "$" in image:
                res.error(f"{dirname}/Dockerfile:{lineno}: FROM image must be explicit, not a variable")
            elif not image_pinned(image):
                res.error(f"{dirname}/Dockerfile:{lineno}: base image must be pinned with @sha256")


def check_hardcoded_flags(record: Path, manifest: dict[str, Any], res: CheckResult) -> None:
    expected = nested(manifest, "flag", "value")
    allowed = {record / "cvex.yml"}
    dataset = record / "dataset"
    target = record / "target"
    runtime_roots = {record / "benign", record / "attacker", record / "recorder"}
    runtime_files = {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
    for path in sorted(record.rglob("*")):
        if not path.is_file() or path in allowed or dataset in path.parents or target in path.parents:
            continue
        if not (path.name in runtime_files or any(root in path.parents for root in runtime_roots)):
            continue
        if path.stat().st_size > 2 * 1024 * 1024 or not is_text(path):
            continue
        text = path.read_text(errors="replace")
        found = FLAG_RE.findall(text)
        if not found:
            continue
        r = rel(path, record)
        if isinstance(expected, str) and expected in found:
            res.error(f"{r}: hard-codes the manifest flag outside target/")
        else:
            res.warn(f"{r}: contains a CVEX-looking flag outside target/")


def check_dataset(record: Path, manifest: dict[str, Any], res: CheckResult) -> None:
    d = record / "dataset"
    res.need_dir(record, "dataset")
    res.need_file(record, "dataset/verdict.json")
    if not d.is_dir():
        return
    for phase in ("benign", "attack"):
        res.need_dir(record, f"dataset/{phase}")
        if not (d / phase / f"{phase}.pcap").is_file():
            res.warn(f"dataset/{phase}/{phase}.pcap is missing")
        if not (d / phase / f"{phase}.syscalls.jsonl").is_file():
            if (d / phase / f"{phase}.syscalls.log").is_file():
                res.warn(f"dataset/{phase}/{phase}.syscalls.log should be converted to .jsonl")
            else:
                res.warn(f"dataset/{phase}/{phase}.syscalls.jsonl is missing")
    if not (d / "flag.observed").is_file() and manifest.get("success") == "flag":
        res.warn("dataset/flag.observed is missing")
    v = d / "verdict.json"
    if v.is_file():
        try:
            verdict = json.loads(v.read_text())
        except ValueError as e:
            res.error(f"dataset/verdict.json is not valid JSON: {e}")
            return
        if not verdict.get("success"):
            res.error("dataset/verdict.json does not report success")
        if verdict.get("cve") and verdict.get("cve") != manifest.get("cve"):
            res.error("dataset/verdict.json `cve` does not match cvex.yml")
        if manifest.get("success") == "flag":
            planted = verdict.get("flag_planted")
            observed = verdict.get("flag_observed")
            if planted and observed and planted != observed:
                res.error("dataset/verdict.json flag_planted and flag_observed differ")


def check_record(record: Path, *, require_dataset: bool = True) -> tuple[CheckResult, dict[str, Any] | None]:
    res = CheckResult()
    if not CVE_RE.match(record.name):
        res.warn("record directory name is not a CVE ID")
    res.need_file(record, "cvex.yml")
    for d in ROLE_DIRS:
        res.need_dir(record, d)
    res.need_file(record, "target/Dockerfile")
    res.need_dir(record, "target/vendor")
    res.need_file(record, "target/plant-flag.sh")
    res.need_file(record, "benign/Dockerfile")
    res.need_file(record, "benign/interact.sh")
    res.need_file(record, "attacker/Dockerfile")
    res.need_file(record, "attacker/exploit.sh")
    res.need_file(record, "recorder/Dockerfile")
    res.need_file(record, "recorder/capture.sh")

    manifest = None
    if (record / "cvex.yml").is_file():
        try:
            manifest = load_manifest(record / "cvex.yml")
            validate_manifest(record, manifest, res)
            check_hardcoded_flags(record, manifest, res)
            if require_dataset:
                check_dataset(record, manifest, res)
        except CvexError as e:
            res.error(str(e))
    check_dockerfiles(record, res)
    return res, manifest


def docker_available() -> None:
    p = run_cmd(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20)
    if p.code != 0:
        raise CvexError("Docker is not available or the daemon is not running:\n" + tail(p.stderr or p.stdout))


def docker(args: list[str], *, timeout: int | None = None) -> CmdResult:
    return run_cmd(["docker", *args], timeout=timeout)


def docker_checked(args: list[str], *, timeout: int | None = None) -> CmdResult:
    p = docker(args, timeout=timeout)
    if p.code != 0:
        raise CvexError("$ docker " + " ".join(shlex.quote(a) for a in args) + "\n" + tail(p.stderr or p.stdout))
    return p


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9_.-]+", "-", text.lower()).strip("-")
    return s[:60] or "cvex"


def port_from_ready(ready: str | None) -> str:
    if isinstance(ready, str) and ready.startswith("tcp:"):
        return ready.split(":", 1)[1]
    return ""


def generate_tags(record: Path, manifest: dict[str, Any]) -> dict[str, str]:
    base = slug(str(manifest.get("cve") or record.name))
    tags = {role: f"cvex-local/{base}-{role}:latest" for role in ROLE_DIRS}
    services = manifest.get("services") or {}
    for svc in services:
        if svc != "target" and (record / svc / "Dockerfile").is_file():
            tags[svc] = f"cvex-local/{base}-{svc}:latest"
    return tags


def build_images(record: Path, manifest: dict[str, Any], tags: dict[str, str],
                 wall: int, logs: list[str]) -> None:
    for role in ("target", "recorder", "benign", "attacker"):
        args = ["build", "-t", tags[role]]
        if role == "target":
            args += ["--network", "none"]
        args.append(str(record / role))
        p = docker(args, timeout=wall)
        logs.append(f"$ docker {' '.join(shlex.quote(a) for a in args)}\n{tail(p.stdout)}{tail(p.stderr)}")
        if p.code != 0:
            raise CvexError(f"building {role} failed:\n" + tail(p.stderr or p.stdout))
    services = manifest.get("services") or {}
    for svc in sorted(k for k in services if k != "target" and k in tags):
        p = docker(["build", "-t", tags[svc], str(record / svc)], timeout=wall)
        logs.append(f"$ docker build -t {tags[svc]} {record / svc}\n{tail(p.stdout)}{tail(p.stderr)}")
        if p.code != 0:
            raise CvexError(f"building {svc} failed:\n" + tail(p.stderr or p.stdout))


def wait_for_file(container: str, path: str, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        p = docker(["exec", container, "test", "-e", path], timeout=5)
        if p.code == 0:
            return True
        time.sleep(0.5)
    return False


def wait_for_tcp(container: str, port: int, timeout_s: int) -> bool:
    hex_port = f"{port:04X}"
    script = ("awk '$4 == \"0A\" { split($2, a, \":\"); "
              f"if (toupper(a[2]) == \"{hex_port}\") found=1 }} "
              "END { exit found ? 0 : 1 }' /proc/net/tcp /proc/net/tcp6 2>/dev/null")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if docker(["exec", container, "sh", "-c", script], timeout=5).code == 0:
            return True
        time.sleep(0.5)
    return False


def wait_ready(container: str, ip: str, ready: str | None, timeout_s: int) -> bool:
    if not ready:
        time.sleep(2)
        return True
    if ready.startswith("file:"):
        return wait_for_file(container, ready.split(":", 1)[1], timeout_s)
    if ready.startswith("tcp:"):
        try:
            port = int(ready.split(":", 1)[1])
        except ValueError:
            return False
        return wait_for_tcp(container, port, timeout_s)
    time.sleep(2)
    return True


def wait_recorder_ready(phase_out: Path, phase: str, timeout_s: int = 30) -> bool:
    marker = phase_out / f".{phase}.ready"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if marker.is_file():
            return True
        time.sleep(0.25)
    return False


def target_has_script(container: str, script: str) -> bool:
    return docker(["exec", container, "test", "-x", script], timeout=5).code == 0


def container_crashed(container: str) -> bool:
    p = docker(["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", container], timeout=10)
    if p.code != 0:
        return False
    parts = p.stdout.strip().split()
    return len(parts) == 2 and parts[0] == "false" and parts[1] not in ("0", "")


def convert_syscalls(phase_out: Path, phase: str) -> bool:
    """Convert the raw strace log to JSONL, capped at SYSCALL_MAX_BYTES.

    Lines past the cap are dropped and a final record says how many, so a
    truncated trace can never be mistaken for a complete one. A raw log larger
    than the cap is removed once converted: it is redundant and just as
    unpushable. A small one is kept, since it costs nothing and helps debugging.
    """
    jsonl = phase_out / f"{phase}.syscalls.jsonl"
    if jsonl.is_file():
        return True
    raw = phase_out / f"{phase}.syscalls.log"
    if not raw.is_file():
        return False
    written = kept = dropped = 0
    with raw.open(errors="replace") as src, jsonl.open("w") as dst:
        for line in src:
            line = line.rstrip("\n")
            if not line:
                continue
            if written >= SYSCALL_MAX_BYTES:
                dropped += 1
                continue
            record = json.dumps({"raw": line}) + "\n"
            dst.write(record)
            written += len(record)
            kept += 1
        if dropped:
            dst.write(json.dumps({"truncated": True, "lines_kept": kept,
                                  "lines_dropped": dropped,
                                  "limit_bytes": SYSCALL_MAX_BYTES}) + "\n")
    if dropped:
        print(f"  {phase}: syscall trace truncated at "
              f"{SYSCALL_MAX_BYTES // (1024 * 1024)} MiB "
              f"({kept} lines kept, {dropped} dropped)", file=sys.stderr)
    if raw.stat().st_size > SYSCALL_MAX_BYTES:
        raw.unlink(missing_ok=True)
    return jsonl.is_file()


def phase_command(manifest: dict[str, Any], phase: str) -> str:
    if phase == "benign":
        return "/benign.sh"
    return "/attack.sh"


def run_phase(record: Path, manifest: dict[str, Any], tags: dict[str, str], phase: str,
              flag: str, out: Path, run_id: str, wall: int) -> PhaseResult:
    phase_out = out / phase
    phase_out.mkdir(parents=True, exist_ok=True)
    network_name = f"cvex-{slug(record.name)}-{phase}-{run_id}"
    containers: list[str] = []
    target_name = f"{network_name}-target"
    recorder_name = f"{network_name}-recorder"
    client_name = f"{network_name}-client"
    services = manifest.get("services") or {}
    target_cfg = services.get("target") or {}
    phases = manifest.get("phases") or {}
    phase_cfg = phases.get(phase) or {}
    target_ip = str(target_cfg.get("ip") or "10.13.0.10")
    client_ip = str(phase_cfg.get("ip") or "")
    ready = target_cfg.get("ready")
    trace = str(target_cfg.get("trace") or "")
    port = port_from_ready(ready)
    subnet = str(nested(manifest, "network", "subnet") or "10.13.0.0/24")
    topology = manifest.get("topology")
    deadline = max(1, int(wall))

    try:
        docker_checked(["network", "create", "--driver", "bridge", "--subnet", subnet, network_name], timeout=20)

        for svc_name, svc in sorted(services.items()):
            if svc_name == "target" or svc_name not in tags:
                continue
            svc_name_full = f"{network_name}-{slug(svc_name)}"
            args = ["run", "-d", "--name", svc_name_full, "--network", network_name,
                    "--network-alias", svc_name]
            if isinstance(svc, dict) and svc.get("ip"):
                args += ["--ip", str(svc["ip"])]
            args.append(tags[svc_name])
            docker_checked(args, timeout=30)
            containers.append(svc_name_full)

        docker_checked(["run", "-d", "--name", target_name, "--network", network_name,
                        "--network-alias", "target", "--ip", target_ip,
                        "-v", f"{phase_out.resolve()}:/out", "-e", f"CVEX_FLAG={flag}",
                        tags["target"]], timeout=30)
        containers.append(target_name)

        plant = ("if [ -x /usr/local/bin/plant-flag.sh ]; then /usr/local/bin/plant-flag.sh; "
                 "elif [ -x /plant-flag.sh ]; then /plant-flag.sh; "
                 "else exit 0; fi")
        docker(["exec", "-e", f"CVEX_FLAG={flag}", target_name, "sh", "-c", plant], timeout=30)

        rec_args = ["run", "-d", "--name", recorder_name, "--network", f"container:{target_name}",
                    "--pid", f"container:{target_name}"]
        for cap in CAPS:
            rec_args += ["--cap-add", cap]
        rec_args += ["-v", f"{phase_out.resolve()}:/out", "-e", f"PHASE={phase}", "-e", "OUTDIR=/out",
                     "-e", f"TRACE={trace}", tags["recorder"]]
        docker_checked(rec_args, timeout=30)
        containers.append(recorder_name)

        rec_ready = wait_recorder_ready(phase_out, phase)
        tgt_ready = wait_ready(target_name, target_ip, ready if isinstance(ready, str) else None,
                               min(90, max(3, deadline // 3)))

        if topology == "single" and target_has_script(target_name, phase_command(manifest, phase)):
            script = phase_command(manifest, phase)
            client = docker(["exec", "-e", "TARGET=target", "-e", f"PORT={port}",
                             "-e", "OUTDIR=/out", target_name, "sh", "-c", script],
                            timeout=deadline)
        else:
            args = ["run", "--rm", "--name", client_name, "--network", network_name,
                    "-e", "TARGET=target", "-e", f"TARGET_IP={target_ip}", "-e", f"PORT={port}",
                    "-e", "OUTDIR=/out", "-v", f"{phase_out.resolve()}:/out"]
            if client_ip:
                args += ["--ip", client_ip]
            args.append(tags["benign" if phase == "benign" else "attacker"])
            client = docker(args, timeout=deadline)

        (phase_out / "stdout.txt").write_text(client.stdout)
        (phase_out / "stderr.txt").write_text(client.stderr)
        (phase_out / "exit_code.txt").write_text(str(client.code) + "\n")
        time.sleep(1)
        crashed = container_crashed(target_name)
        docker(["stop", "-t", "5", recorder_name], timeout=15)
        syscalls = convert_syscalls(phase_out, phase)
        pcap = (phase_out / f"{phase}.pcap").is_file()
        return PhaseResult(phase, client.code, client.stdout, client.stderr, pcap, syscalls,
                           rec_ready and tgt_ready, crashed)
    finally:
        for c in reversed(containers):
            docker(["rm", "-f", c], timeout=15)
        docker(["network", "rm", network_name], timeout=15)


def find_flag_in_text(text: str) -> str | None:
    m = FLAG_LINE_RE.search(text)
    if m:
        return m.group(1)
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def bytes_contain(path: Path, needle: str) -> bool:
    if not path.is_file():
        return False
    try:
        return needle.encode() in path.read_bytes()
    except OSError:
        return False


def observed_flag(out: Path, attack: PhaseResult, channel: str, flag: str) -> str | None:
    if channel == "network":
        pcap = out / "attack" / "attack.pcap"
        if bytes_contain(pcap, flag):
            return flag
    if channel == "file":
        f = out / "attack" / "flag.observed"
        if f.is_file():
            return find_flag_in_text(f.read_text(errors="replace"))
    found = find_flag_in_text(attack.stdout + "\n" + attack.stderr)
    if found:
        return found
    if channel == "network":
        pcap = out / "attack" / "attack.pcap"
        if pcap.is_file():
            data = pcap.read_bytes()
            m = re.search(rb"CVEX\{[0-9a-fA-F]{32}\}", data)
            if m:
                return m.group(0).decode()
    return None


def benign_leaked(out: Path, benign: PhaseResult, flag: str) -> bool:
    if flag in benign.stdout or flag in benign.stderr:
        return True
    if bytes_contain(out / "benign" / "benign.pcap", flag):
        return True
    f = out / "benign" / "flag.observed"
    return f.is_file() and flag in f.read_text(errors="replace")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(out: Path) -> None:
    lines: list[str] = []
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"):
        lines.append(f"{sha256_file(path)}  {path.relative_to(out).as_posix()}")
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + ("\n" if lines else ""))


def safe_prepare_out(out: Path, record: Path) -> None:
    out = out.resolve()
    record = record.resolve()
    if out == record or out == record.parent or out == Path("/"):
        raise CvexError(f"refusing to write dataset to unsafe path: {out}")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)


def run_record(record: Path, out: Path, fresh_flag: bool, skip_check: bool = False,
               no_build: bool = False) -> dict[str, Any]:
    if not skip_check:
        res, manifest = check_record(record, require_dataset=False)
        if manifest is None:
            raise CvexError("cannot run without a valid cvex.yml")
        if res.errors:
            raise CvexError("check failed; fix these first:\n- " + "\n- ".join(res.errors[:12]))
    else:
        manifest = load_manifest(record / "cvex.yml")
    docker_available()
    safe_prepare_out(out, record)

    flag = nested(manifest, "flag", "value")
    if fresh_flag or not isinstance(flag, str):
        flag = f"CVEX{{{secrets.token_hex(16)}}}"
    wall = int(nested(manifest, "limits", "wall_clock_seconds") or 600)
    tags = generate_tags(record, manifest)
    build_logs: list[str] = []
    if not no_build:
        build_images(record, manifest, tags, wall, build_logs)
    if build_logs:
        (out / "build.log").write_text("\n\n".join(build_logs))

    run_id = secrets.token_hex(4)
    benign = run_phase(record, manifest, tags, "benign", flag, out, run_id, wall)
    attack = run_phase(record, manifest, tags, "attack", flag, out, run_id, wall)

    channel = str(nested(manifest, "capture", "flag_channel") or "stdout")
    criterion = str(manifest.get("success") or "flag")
    observed = observed_flag(out, attack, channel, flag) if criterion == "flag" else None
    leak = benign_leaked(out, benign, flag) if criterion == "flag" else False
    flag_match = criterion == "flag" and observed == flag
    crash_success = criterion == "crash" and attack.target_crashed and not benign.target_crashed
    success = bool((flag_match or crash_success) and benign.exit_code == 0 and not leak)

    if observed:
        (out / "flag.observed").write_text(observed + "\n")
    verdict = {
        "cve": manifest.get("cve"),
        "success": success,
        "criterion": criterion,
        "channel": channel,
        "flag_planted": flag if criterion == "flag" else None,
        "flag_observed": observed,
        "flag_match": flag_match if criterion == "flag" else None,
        "benign_ok": benign.exit_code == 0,
        "benign_leak": leak,
        "attack_ok": attack.exit_code == 0,
        "benign": {
            "exit_code": benign.exit_code,
            "ready": benign.ready,
            "pcap": benign.pcap,
            "syscalls": benign.syscalls,
            "target_crashed": benign.target_crashed,
        },
        "attack": {
            "exit_code": attack.exit_code,
            "ready": attack.ready,
            "pcap": attack.pcap,
            "syscalls": attack.syscalls,
            "target_crashed": attack.target_crashed,
        },
    }
    write_json(out / "verdict.json", verdict)
    write_manifest(out)
    return verdict


def verify_record(record: Path, out: Path | None, fresh_flag: bool) -> dict[str, Any]:
    committed = record / "dataset" / "verdict.json"
    if not committed.is_file():
        raise CvexError("cannot verify: committed dataset/verdict.json is missing")
    try:
        committed_verdict = json.loads(committed.read_text())
    except ValueError as e:
        raise CvexError(f"committed dataset/verdict.json is not valid JSON: {e}") from e
    with tempfile.TemporaryDirectory(prefix="cvex-verify-") as tmp:
        run_out = out or Path(tmp) / "dataset"
        verdict = run_record(record, run_out, fresh_flag=fresh_flag, skip_check=False)
        ok = bool(committed_verdict.get("success") and verdict.get("success"))
        return {
            "ok": ok,
            "committed_success": bool(committed_verdict.get("success")),
            "fresh_success": bool(verdict.get("success")),
            "fresh_out": str(run_out),
        }


def print_check(res: CheckResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(res.to_json(), indent=2, sort_keys=True))
        return
    if res.ok:
        print("check: ok")
    else:
        print("check: failed")
    for e in res.errors:
        print(f"ERROR: {e}")
    for w in res.warnings:
        print(f"WARNING: {w}")


def cmd_check(args: argparse.Namespace) -> int:
    try:
        record = resolve_record(args.record)
        res, _ = check_record(record)
        print_check(res, args.json)
        return 0 if res.ok else 1
    except CvexError as e:
        if args.json:
            print(json.dumps({"ok": False, "errors": [str(e)], "warnings": []}, indent=2))
        else:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    try:
        record = resolve_record(args.record)
        out = Path(args.out).resolve() if args.out else (record / "dataset")
        verdict = run_record(record, out, fresh_flag=args.fresh_flag, skip_check=args.skip_check,
                             no_build=args.no_build)
        if args.json:
            print(json.dumps(verdict, indent=2, sort_keys=True))
        else:
            print(f"wrote {out}")
            print(f"success: {str(verdict.get('success')).lower()}")
            if verdict.get("flag_observed"):
                print(f"observed: {verdict['flag_observed']}")
        return 0 if verdict.get("success") else 1
    except CvexError as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        record = resolve_record(args.record)
        out = Path(args.out).resolve() if args.out else None
        result = verify_record(record, out, fresh_flag=args.fresh_flag)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("verify: " + ("ok" if result["ok"] else "failed"))
            print(f"committed success: {str(result['committed_success']).lower()}")
            print(f"fresh success: {str(result['fresh_success']).lower()}")
            if args.out:
                print(f"fresh dataset: {result['fresh_out']}")
        return 0 if result["ok"] else 1
    except CvexError as e:
        if args.json:
            print(json.dumps({"ok": False, "error": str(e)}, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CVEX v3 checker and runner")
    sp = p.add_subparsers(dest="cmd", required=True)

    c = sp.add_parser("check", help="static validation of a CVEX record")
    c.add_argument("record")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_check)

    r = sp.add_parser("run", help="build and run benign/attack phases")
    r.add_argument("record")
    r.add_argument("--fresh-flag", action="store_true", help="plant a new random flag for this run")
    r.add_argument("--out", help="dataset output directory; default: RECORD/dataset")
    r.add_argument("--json", action="store_true")
    r.add_argument("--skip-check", action="store_true", help="run even if static check would fail")
    r.add_argument("--no-build", action="store_true", help="reuse existing local image tags")
    r.set_defaults(func=cmd_run)

    v = sp.add_parser("verify", help="rerun and compare success with the committed dataset")
    v.add_argument("record")
    v.add_argument("--fresh-flag", action="store_true", default=True,
                   help="plant a new random flag for the verification run")
    v.add_argument("--out", help="keep the fresh verification dataset at this path")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
