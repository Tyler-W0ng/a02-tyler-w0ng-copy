#!/usr/bin/env python3
"""CS279 preflight: does this repository contain what the grader needs?

    python3 .cs279/preflight.py                  # check the repository you are in
    python3 .cs279/preflight.py --repo PATH      # check another checkout
    python3 .cs279/preflight.py --findings output/items   # A05/A06: validate pipeline output
    python3 .cs279/preflight.py --json           # machine-readable result

Fast and deterministic: it reads files, never runs your code, and grades
nothing. Python 3.11+ works with the standard library; Python 3.10 also works
if `tomli` is installed. The finding-schema check uses the `jsonschema` package
if it is installed, and a simpler structural check if it is not.

The course grader runs its own copy of this file. Editing yours changes nothing.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        print("preflight requires Python 3.11+, or Python 3.10 with `tomli` installed.",
              file=sys.stderr)
        raise SystemExit(2)

HERE = Path(__file__).resolve().parent
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class Result:
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str):
        self.errors.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    def need(self, root: Path, *paths: str, kind: str = "file"):
        for p in paths:
            q = root / p
            ok = q.is_file() if kind == "file" else q.is_dir()
            if not ok:
                self.error(f"missing {kind}: {p}")
            elif kind == "file" and q.stat().st_size == 0:
                self.error(f"empty file: {p}")


def load_toml(path: Path, res: Result) -> dict:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        res.error(f"missing file: {path.name}")
    except tomllib.TOMLDecodeError as e:
        res.error(f"{path.name} is not valid TOML: {e}")
    return {}


def common(root: Path, res: Result, group: bool) -> dict:
    sub = load_toml(root / "submission.toml", res)
    a = str(sub.get("assignment", "")).upper()
    if not re.fullmatch(r"A0[1-7]", a):
        res.error('submission.toml: `assignment` must be "A01" ... "A06"')
    members = sub.get("members")
    if not isinstance(members, list) or not members or not all(isinstance(m, str) and m for m in members):
        res.error("submission.toml: `members` must be a non-empty list of GitHub usernames")
    elif any(re.fullmatch(r"\d{7}", m) for m in members):
        res.error("submission.toml: list GitHub usernames, never student IDs")
    res.need(root, "AI_USAGE.md")
    if group:
        res.need(root, "CONTRIBUTIONS.md")
    ai = root / "AI_USAGE.md"
    if ai.is_file() and "TODO" in ai.read_text(errors="replace"):
        res.warn("AI_USAGE.md still contains TODO")
    return sub


def report(root: Path, res: Result):
    if not (root / "REPORT.md").is_file() and not (root / "REPORT.pdf").is_file():
        res.error("missing REPORT.md (or REPORT.pdf)")


# --- code that is not in the commit --------------------------------------------

def uncommitted(root: Path, dirs: list[str], res: Result):
    """Files under `dirs` that git does not track: they exist on your machine,
    so your images build here, but the grader checks out the commit only."""
    if not (root / ".git").exists():
        return
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard",
                              "--", *dirs], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return
    files = out.split()
    if files:
        more = f" (and {len(files) - 8} more)" if len(files) > 8 else ""
        res.warn("not committed, so the grader will not see them: " + ", ".join(files[:8]) + more +
                 " (`git add` them; `git commit -a` skips new files)")


def copied_files(root: Path, dirs: list[str], res: Result):
    """What a Dockerfile COPYs from its context must be in the repository."""
    for top in dirs:
        df = root / top / "Dockerfile"
        if not df.is_file():
            continue
        text = re.sub(r"\\\n", " ", df.read_text(errors="replace"))
        for line in text.splitlines():
            words = line.split()
            if not words or words[0].upper() not in ("COPY", "ADD"):
                continue
            args = [w for w in words[1:] if not w.startswith("--")]
            if any(w.startswith("--from") for w in words) or len(args) < 2:
                continue
            for src in args[:-1]:
                if src.startswith(("http://", "https://", "[")) or any(c in src for c in "*?$"):
                    continue
                if not (root / top / src).exists():
                    res.error(f"{top}/Dockerfile copies {src}, which is not in the repository")


def local_imports(root: Path, dirs: list[str], res: Result):
    """Every import of your own modules must resolve to a file in the repository."""
    for top in dirs:
        d = root / top
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.py")):
            try:
                tree = ast.parse(f.read_text(errors="replace"))
            except SyntaxError as e:
                res.error(f"{f.relative_to(root)}: syntax error ({e.msg}, line {e.lineno})")
                continue
            # Where Python may find a top-level module: the file's directory or
            # one of its parents inside `top` (the image's WORKDIR is one of them).
            bases = [p for p in [f.parent, *f.parent.parents] if p == d or d in p.parents]
            for node in ast.walk(tree):
                where = f"{f.relative_to(root)}:{node.lineno}" if hasattr(node, "lineno") else ""
                if isinstance(node, ast.Import):
                    targets = [(None, a.name, []) for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level:      # from .x import y
                    base = f.parent
                    for _ in range(node.level - 1):
                        base = base.parent
                    targets = [(base, node.module or "", [a.name for a in node.names])]
                elif isinstance(node, ast.ImportFrom):
                    targets = [(None, node.module or "", [a.name for a in node.names])]
                else:
                    continue
                for home, mod, names in targets:
                    if home is None:
                        first = mod.split(".")[0]
                        home = next((b for b in bases
                                     if (b / first).is_dir() or (b / f"{first}.py").is_file()), None)
                        if home is None:       # the standard library or an installed package
                            continue
                    path = home.joinpath(*mod.split(".")) if mod else home
                    if not (path.with_suffix(".py").is_file() or path.is_dir()):
                        res.error(f"{where}: imports `{mod}`, but "
                                  f"{path.relative_to(root)}.py is not in the repository")
                        continue
                    if path.is_dir():                  # from package import name: a module or a name
                        init = path / "__init__.py"
                        text = init.read_text(errors="replace") if init.is_file() else ""
                        for n in names:
                            if n != "*" and not ((path / f"{n}.py").is_file() or (path / n).is_dir()
                                                 or re.search(rf"\b{re.escape(n)}\b", text)):
                                res.error(f"{where}: imports `{n}` from `{mod or '.'}`, but "
                                          f"{(path / n).relative_to(root)}.py is not in the repository")


# --- per assignment ------------------------------------------------------------

def a01(root, sub, res):
    res.need(root, "agent/Dockerfile", "mcp/Dockerfile", "compose.yaml")
    uncommitted(root, ["agent", "mcp"], res)
    copied_files(root, ["agent", "mcp"], res)
    local_imports(root, ["agent", "mcp"], res)
    report(root, res)


def a02(root, sub, res):
    rec = str(sub.get("record", ""))
    if not CVE_RE.match(rec):
        res.error('submission.toml: `record` must be the CVE ID, e.g. "CVE-2023-12345"')
        return
    d = root / rec
    if not d.is_dir():
        res.error(f"missing record directory: {rec}/")
        return
    res.need(root, f"{rec}/cvex.yml", f"{rec}/target/Dockerfile", f"{rec}/target/plant-flag.sh")
    res.need(root, f"{rec}/dataset/verdict.json")
    existing = HERE / "existing_records.txt"
    if existing.is_file():
        known = {l.strip() for l in existing.read_text().splitlines() if l.strip() and not l.startswith("#")}
        if rec in known:
            res.error(f"{rec} already has a CVEX record; choose another CVE")
    v = d / "dataset" / "verdict.json"
    if v.is_file():
        try:
            if not json.loads(v.read_text()).get("success"):
                res.warn("dataset/verdict.json does not report success")
        except ValueError:
            res.error("dataset/verdict.json is not valid JSON")
    big = [p for p in d.rglob("*") if p.is_file() and p.stat().st_size > 95 * 2**20]
    for p in big:
        res.error(f"{p.relative_to(root)} is over GitHub's 100 MB file limit")
    cvex = HERE / "cvex.py"
    if cvex.is_file():
        res.warn(f"also run: python3 .cs279/cvex.py check {rec}")
    report(root, res)


def pipeline(root, sub, res):
    res.need(root, "compose.yaml", "Makefile")
    res.need(root, "input/items", kind="dir")
    report(root, res)


def a03(root, sub, res):
    res.need(root, "slides.pdf", "REPORT.md", "sample.csv")
    res.need(root, "scripts", kind="dir")
    names = sub.get("datasets")
    if not (isinstance(names, list) and len(names) == 3 and all(isinstance(n, str) and n for n in names)):
        res.error("submission.toml: `datasets` must list your three datasets")
        names = []
    p = root / "sample.csv"
    if not p.is_file():
        return
    with open(p, newline="") as f:
        rows = list(csv.DictReader(f))
    need = {"dataset", "entry_id", "classification", "missing", "notes"}
    if not rows or not need <= set(rows[0]):
        res.error(f"sample.csv: header must be {','.join(sorted(need))}")
        return
    per: dict[str, int] = {}
    for i, r in enumerate(rows, 2):
        c = (r["classification"] or "").strip()
        if c not in ("ready", "partial", "unusable"):
            res.error(f"sample.csv line {i}: classification must be ready, partial or unusable")
        if c in ("partial", "unusable") and not (r["missing"] or "").strip():
            res.error(f"sample.csv line {i}: say what is missing for a {c} entry")
        if not (r["entry_id"] or "").strip():
            res.error(f"sample.csv line {i}: empty entry_id")
        per[(r["dataset"] or "").strip()] = per.get((r["dataset"] or "").strip(), 0) + 1
    for n in names:
        if per.get(n, 0) != 20:
            res.error(f"sample.csv: dataset {n!r} has {per.get(n, 0)} rows, expected 20")
    for n in per:
        if names and n not in names:
            res.error(f"sample.csv: dataset {n!r} is not in submission.toml")


def a04(root, sub, res):
    res.need(root, "app/Dockerfile", "app/app.toml", "app/SPEC.md", "tests/Dockerfile",
             "solution/VULNERABILITY.md", "solution/exploit/Dockerfile",
             "solution/oracle/run.sh", "solution/fix.patch")
    app = load_toml(root / "app" / "app.toml", res) if (root / "app" / "app.toml").is_file() else {}
    if app:
        if not isinstance(app.get("port"), int):
            res.error("app.toml: `port` must be an integer")
        if app.get("protocol") not in ("http", "tcp"):
            res.error('app.toml: `protocol` must be "http" or "tcp"')
        ready = str(app.get("ready", ""))
        if not (ready == "tcp" or ready.startswith("http:/")):
            res.error('app.toml: `ready` must be "tcp" or "http:/<path>"')
        wf = app.get("workflows", [])
        ids = [w.get("id") for w in wf if isinstance(w, dict)]
        if len(set(ids)) < 5 or None in ids:
            res.error("app.toml: declare at least 5 workflows, each with a unique `id`")
        rules = app.get("rules", [])
        if len(rules) < 10:
            res.error("app.toml: declare at least 10 rules")
        if sub.get("rule") not in rules:
            res.error("submission.toml: `rule` must be one of the rules in app.toml")
    spec = root / "app" / "SPEC.md"
    if spec.is_file() and app:
        text = spec.read_text(errors="replace")
        for r in app.get("rules", []):
            if not re.search(rf"\b{re.escape(str(r))}\b", text):
                res.error(f"SPEC.md does not define rule {r}")
    leaks = [p for p in (root / "app").rglob("*") if p.is_file() and
             re.search(r"exploit|solution|vuln|backdoor|fix\.patch", p.name, re.I)]
    for p in leaks:
        res.warn(f"app/ is shipped to A06: does {p.relative_to(root)} hint at the solution?")


# --- finding reports (A05, A06) -------------------------------------------------

def findings(out_dir: Path, res: Result, logic: bool):
    schema_path = HERE / "finding.schema.json"
    schema = json.loads(schema_path.read_text()) if schema_path.is_file() else None
    try:
        import jsonschema  # type: ignore
    except ImportError:
        jsonschema = None
    targets = [d for d in sorted(out_dir.iterdir()) if d.is_dir()] if out_dir.is_dir() else []
    if not targets:
        res.error(f"{out_dir}: no target directories")
    for t in targets:
        s = t / "summary.json"
        if not s.is_file():
            res.error(f"{t.name}: missing summary.json")
        for rep in sorted(t.glob("findings/*/report.json")):
            where = rep.relative_to(out_dir)
            try:
                doc = json.loads(rep.read_text())
            except ValueError as e:
                res.error(f"{where}: invalid JSON ({e})")
                continue
            if schema and jsonschema:
                for err in jsonschema.Draft202012Validator(schema).iter_errors(doc):
                    res.error(f"{where}: {'/'.join(map(str, err.path)) or '(root)'}: {err.message}")
            else:
                for k in ("schema_version", "target", "finding", "location", "root_cause",
                          "evidence", "reproduction", "impact", "validation"):
                    if k not in doc:
                        res.error(f"{where}: missing `{k}`")
            if logic and not doc.get("logic"):
                res.error(f"{where}: A06 findings need the `logic` section")
            fdir = rep.parent
            for ev in doc.get("evidence", []) or []:
                p = (fdir / str(ev.get("path", ""))).resolve()
                if not str(p).startswith(str(fdir.resolve())) or not p.is_file():
                    res.error(f"{where}: evidence path {ev.get('path')!r} missing or outside the finding")
            rp = ((doc.get("reproduction") or {}).get("replay") or {}).get("context")
            state = (doc.get("validation") or {}).get("state")
            if state in ("reproducible", "confirmed_bug", "confirmed_vulnerability"):
                if not rp or not (fdir / rp / "Dockerfile").is_file():
                    res.error(f"{where}: a {state} finding needs reproduction.replay.context with a Dockerfile")


CHECKS = {"A01": a01, "A02": a02, "A03": a03, "A04": a04,
          "A05": pipeline, "A06": pipeline}
GROUP = {"A03", "A05", "A06"}


def check(root: Path, findings_dir: Path | None = None) -> Result:
    res = Result()
    sub = common(root, res, group=False)
    a = str(sub.get("assignment", "")).upper()
    if a in GROUP:
        res.need(root, "CONTRIBUTIONS.md")
    if a in CHECKS:
        CHECKS[a](root, sub, res)
    if findings_dir is not None:
        findings(findings_dir, res, logic=(a == "A06"))
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--repo", type=Path, default=None)
    ap.add_argument("--findings", type=Path, default=None, help="A05/A06 output directory to validate")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    root = (args.repo or (HERE.parent if HERE.name == ".cs279" else Path.cwd())).resolve()
    res = check(root, args.findings)
    if args.json:
        print(json.dumps({"ok": not res.errors, "errors": res.errors, "warnings": res.warnings}, indent=1))
    else:
        for w in res.warnings:
            print(f"warning: {w}")
        for e in res.errors:
            print(f"ERROR:   {e}")
        print("preflight: OK" if not res.errors else f"preflight: {len(res.errors)} error(s)")
    return 1 if res.errors else 0


if __name__ == "__main__":
    sys.exit(main())
