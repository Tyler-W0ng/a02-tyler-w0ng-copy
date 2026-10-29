# AI usage

**Tool/model.** Kiro (agentic assistant) running Claude Opus 4.8.

**What it was used for.**

- **Vulnerability research and verification.** Fetching the upstream Wisp source
  at tags `v2.2.0` and `v2.2.1`, the fix commit
  `161118c431047f7ef1ff7cabfcc38981877fdd93`, and the GitHub Security Advisory
  API for GHSA-h7cj-j2vv-qw8r, then explaining the decode-after-strip root cause.
- **The record.** Writing the Gleam static-site app (`target/src/static_site.gleam`
  and the static assets), all four Dockerfiles, `plant-flag.sh`,
  `benign/interact.sh`, `attacker/exploit.sh`, `recorder/capture.sh`, `cvex.yml`,
  and this repository's `submission.toml`.
- **The offline build.** Diagnosing that Wisp 2.2.0 is retired on Hex and
  vendoring it as a path dependency; bisecting the `gleam_stdlib`/`glisten`
  `list.range` incompatibility and capping stdlib to 0.70.0; wiring the vendored
  `build/packages` so `docker build --network none` works.
- **Writing `REPORT.md`** and this file.

**How the output was checked.** The claims are backed by execution, not by the
model's say-so. The target image builds with `docker build --network none`. The
course runner (`.cs279/cvex.py run --fresh-flag`) was run and reports
`success: true`, with the attack capturing the fresh planted flag over the
network and the benign client exiting 0 without ever seeing it; the committed
`dataset/verdict.json` is that run's output. The exploit and the benign request
were also exercised by hand against the running container. Every code-level
statement in `REPORT.md` was checked against the fetched upstream source, the
fix commit diff, and the advisory API response (CWE-22, affected `>= 2.1.1,
< 2.2.1`, patched 2.2.1, CVSS v4 8.7), rather than taken from the model's memory.
I reviewed all generated files and own the result.
