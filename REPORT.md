# CVE-2026-28807 — Path traversal in Wisp's `serve_static`

## 1. The vulnerability

**Software.** [Wisp](https://github.com/gleam-wisp/wisp) is a web framework for
[Gleam](https://gleam.run), a statically typed language that compiles to
Erlang/BEAM. It is distributed as the Hex package `wisp` under the Apache-2.0
licence (`vendor/wisp/LICENCE`, and `licences = ["Apache-2.0"]` in
`vendor/wisp/gleam.toml`). It is maintained by Louis Pilfold, the creator of
Gleam. The project is actively developed: v2.2.0 was released 2026-01-16, the
security fix v2.2.1 on 2026-03-08, and the advisory was published 2026-03-11.
The fix commit below is signed by the maintainer and ships new regression tests,
which is the behaviour of a maintained project.

**Identifiers.** GHSA-h7cj-j2vv-qw8r / CVE-2026-28807. CWE-22 (Improper
Limitation of a Pathname to a Restricted Directory). Severity High:
CVSS v4.0 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N` = 8.7, and
CVSS v3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5.
Affected: `>= 2.1.1, < 2.2.1`. Fixed in `2.2.1`. **This record targets 2.2.0.**

**Where it lives.** `src/wisp.gleam`, in the `serve_static` middleware. In 2.2.0
the request path is sanitised and joined to the served directory, and only
*after* that is it percent-decoded:

```gleam
// wisp 2.2.0, src/wisp.gleam (serve_static)
let path =
  path
  |> string.drop_start(string.length(prefix))
  |> string.replace(each: "..", with: "")   // (1) strip literal ".."
  |> filepath.join(directory, _)             // (2) join to the served dir

let path = case uri.percent_decode(path) {    // (3) decode AFTER stripping
  Ok(p) -> p
  Error(_) -> path
}
```

**Root cause.** The order of operations. Step (1) removes only *literal* `..`
substrings. A request path containing the percent-encoded form `%2e%2e` has no
literal `..`, so it passes the filter untouched. Step (3) then percent-decodes
`%2e%2e` into `..` — but the `..` filter has already run and the path has
already been joined to the served directory. The decoded `..` segments are
resolved by the operating system when the file is opened, so the request
escapes the served directory and reads arbitrary files the server process can
access.

**The fix (v2.2.1, commit `161118c431047f7ef1ff7cabfcc38981877fdd93`).** Decode
first, then strip:

```gleam
let path =
  path
  |> string.drop_start(string.length(prefix))
  |> uri.percent_decode        // decode FIRST
  |> result.unwrap(path)
  |> string.replace(each: "..", with: "")   // then strip ".."
  |> filepath.join(directory, _)
```

Now `%2e%2e` is decoded to `..` *before* `string.replace` runs, so the filter
removes it. The same commit adds `serve_static_path_traversal_attack_uri_encoded_test`,
which asserts that `/%2e%2e/gleam.toml` is not served.

**Remote attack path and preconditions.** `serve_static` *is* the HTTP request
handler for the static-file route — it is the network-facing interface, invoked
on every incoming GET to the configured prefix. The only precondition is that
the application serves static files the documented way,
`wisp.serve_static(under: ..., from: ...)`, which is the framework's single
intended mechanism for static assets (its doc comment shows exactly this). No
authentication, session, or prior access is required. The attacker sends one
unauthenticated HTTP GET whose path contains `%2e%2e` segments. The only
attacker-side detail is sending the request with the encoded segments intact;
with `curl` this is `--path-as-is`, which stops the *client* from collapsing
`..` locally. That is a property of the attacker's own tooling, not of the
target.

## 2. The record

**Topology.** `target-attacker` (manifest `cvex.yml`). The target is a long-lived
HTTP server; the benign and attack clients each run in a separate container and
reach it over the Docker network at `http://target:8080`.

**Target.** `target/` is a small but genuine static website ("Acme Widgets",
`target/src/static_site.gleam`). It builds the Wisp handler with the `mist`
HTTP server adapter (`wisp_mist.handler |> mist.new |> mist.port(8080) |>
mist.bind("0.0.0.0") |> mist.start`) and serves its public assets with

```gleam
wisp.serve_static(req, under: "/static", from: "/app/priv/static")
```

It exposes exactly two things: a home page at `/` (static HTML, no secret) and
the files under `/static/*`. `target/priv/static/` holds the real assets
(`style.css`, `logo.svg`) that the home page links to.

**Why the configuration is realistic.** Serving a fixed assets directory with
`serve_static` is the framework's documented, intended use; the `serve_static`
doc comment itself gives `from: "/public"` and `from: priv` as examples, so an
absolute `from: "/app/priv/static"` is an ordinary deployment choice, not a
contrivance. The one non-default build setting is in `target/gleam.toml`:
`gleam_stdlib` is capped to `< 0.71.0`. This is a pure build-time version pin,
explained in §4; it does not touch the vulnerable code or the runtime behaviour.

**Offline build.** `target/Dockerfile` starts from the Gleam image pinned by
digest (`ghcr.io/gleam-lang/gleam@sha256:64b1df35…`, i.e. v1.19.2-erlang-alpine;
Wisp requires Gleam ≥ 1.11.0). Every dependency is vendored under
`target/vendor/`: Wisp 2.2.0 as a local *path* dependency in `vendor/wisp/`, and
the 24 resolved Hex packages, unpacked exactly as `gleam deps download` leaves
them, in `vendor/packages/`. The build copies `vendor/packages` into Gleam's
`build/packages` and runs `gleam export erlang-shipment`, so it never contacts
Hex. `docker build --network none target/` succeeds, and the container runs the
compiled Erlang release (no Gleam or Hex involvement at runtime).

**Flag gate.** The runner plants a fresh random flag each run via
`target/plant-flag.sh`, which writes `$CVEX_FLAG` to `/app/secret/flag.txt`.
That path is **outside** the served root `/app/priv/static` — two directories
above it. Nothing the server exposes references the secret: the home page is
fixed HTML, and `/static/*` only ever reads files beneath `/app/priv/static`.
A legitimate client therefore cannot reach the flag by any route. Only the
CVE-2026-28807 traversal escapes the served directory:
`/static/%2e%2e/%2e%2e/secret/flag.txt` resolves to `/app/secret/flag.txt`. The
gate adds no helper, weakens no permissions (the flag file is `0644`, readable
by the server because the server reads *every* file it serves), and hard-codes
no flag in the target.

**Benign client.** `benign/interact.sh` fetches `/`, then `/static/style.css`
and `/static/logo.svg` — the same `serve_static` feature the attack abuses, used
the way a browser would. It is a fair counterpart: identical endpoint and
feature, ordinary (non-encoded, in-root) paths. It completes with exit 0 and
never observes the flag (verified: `benign_leak: false`, `benign_ok: true`).

**Attacker.** `attacker/exploit.sh` sends the single unauthenticated GET
`http://target:8080/static/%2e%2e/%2e%2e/secret/flag.txt` with `--path-as-is`,
prints the response body (the flag) to stdout — the manifest's
`capture.flag_channel: stdout` — and, to show the impact is arbitrary file read
rather than one special file, also reads `/etc/passwd` through a deeper
traversal. It reads the flag dynamically from the response; no flag value is
baked in.

**Recorder.** `recorder/capture.sh` shares the target's network and PID
namespaces and records a packet capture (`*.pcap`) and a syscall trace of the
BEAM process (`*.syscalls.jsonl`) for each phase. The target runs on BEAM, not a
JVM, so the traces are a few megabytes and are not truncated.

**Committed dataset.** `dataset/` is a full reference run produced by the course
runner with a fresh flag. `dataset/verdict.json` reports `success: true` with
`flag_planted == flag_observed`, `benign_ok: true`, and `benign_leak: false`.

## 3. Provenance

All artifacts are vendored into the record; nothing is fetched at build or run
time.

| Artifact | Version | Source | Integrity | Licence |
|---|---|---|---|---|
| Wisp (target framework, path dep) | 2.2.0 | Hex tarball `wisp-2.2.0.tar` (`https://repo.hex.pm/tarballs/wisp-2.2.0.tar`) | tarball SHA-256 `655163d4de19e3dd4ac75813a991bfd5523cb4ff2fc5f9f58fd6fb39d5d1806d`; Hex CHECKSUM `F598764B2BAA84C3255402CE10171E4556896ECDB6003C9F82FA639FEE7709A6` | Apache-2.0 (`vendor/wisp/LICENCE`) |
| 24 Hex dependencies (`mist` 5.0.4, `glisten` 8.0.3, `gleam_stdlib` 0.70.0, …) | see `target/manifest.toml` | Hex, resolved by `gleam deps download` | per-package `outer_checksum` recorded in `target/manifest.toml` | respective OSS licences, retained in each `vendor/packages/<pkg>/` |
| Target base image | Gleam v1.19.2-erlang-alpine | `ghcr.io/gleam-lang/gleam` | `@sha256:64b1df35a9611332d51f77c97f16f50ec97863162ba8824400ed4c8dff6378ac` | — |
| Benign/attacker/recorder base image | Alpine 3.21 | `docker.io/library/alpine` | `@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd` | — |

The exploit script is my own work. The underlying technique (percent-encoded
`..` to defeat a pre-decode `..` filter) is described in the public advisory
GHSA-h7cj-j2vv-qw8r; the code-level analysis in §1 is confirmed against the
upstream source at tags `v2.2.0` and `v2.2.1` and against the fix commit
`161118c431047f7ef1ff7cabfcc38981877fdd93`.

## 4. What it took

The vulnerability is a two-line order-of-operations bug and was quick to confirm
by reading `src/wisp.gleam` at `v2.2.0` and `v2.2.1`. Nearly all the effort went
into building Wisp 2.2.0 offline.

1. **Wisp 2.2.0 is retired on Hex.** The maintainer retired the vulnerable
   release, so Gleam's resolver refuses it (`wisp@2.2.0 is retired`). I vendored
   it from its published Hex tarball and declared it as a local *path*
   dependency (`wisp = { path = "./vendor/wisp" }`), which also satisfies the
   "vendored, not fetched" rule. Its non-retired transitive dependencies resolve
   normally.

2. **A newer toolchain broke an older dependency.** With the current Gleam
   (1.19.2) the resolver picked `gleam_stdlib` 0.71.0, which removed
   `list.range`; `glisten` 8.0.3 (pulled in transitively through `mist`, which
   Wisp 2.2.0 depends on) still calls it, so the build failed. I bisected the
   stdlib tags, found `list.range` present through 0.70.0 and gone in 0.71.0,
   and capped `gleam_stdlib` to `< 0.71.0`. `glisten` allows
   `>= 0.59.0 and < 1.0.0`, so 0.70.0 satisfies every constraint.

3. **Truly offline build.** `docker build --network none` forbids
   `gleam deps download`, so I pre-populate Gleam's `build/packages` from the
   vendored sources and run `gleam export erlang-shipment`. Getting Gleam to
   compile from a pre-filled package directory without reaching for Hex was the
   fiddliest part.

4. **Traversal depth.** I found empirically that two `%2e%2e` segments are
   needed to climb from `/app/priv/static` to `/app/secret`.

The mechanical steps (resolving and vendoring dependencies, pinning digests,
wiring the compose-less runner contract, capturing packets and syscalls) are
automatable. The judgement calls are not: recognising that a *framework* CVE is
legitimately exercised through its documented static-file handler, diagnosing
the retirement and choosing the path-dependency workaround, bisecting the
stdlib incompatibility, and reasoning that the flag placement is sound (that no
legitimate route reaches `/app/secret`). End to end this took a few hours,
dominated by items 1–3.
