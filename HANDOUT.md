# A02: A CVEX v3 record, by hand

**Individual.** Read [the submission guide](../SUBMISSION.md) first. Dates are
on the course schedule.

You will create one **CVEX v3 record** for a CVE that does not have one yet.
A record is a self-contained, reproducible Docker project for a single
vulnerability, verified by a planted flag. The format is defined in the
upstream [`CVEX_v3_DESIGN.md`](https://github.com/ucsb-seclab/CVEX-v3/blob/main/CVEX_v3_DESIGN.md).
Read the design document in full before you choose a CVE.

The reference records are not copied into this repository. The three records to
study are described in
[`REFERENCE_RECORDS.md`](https://github.com/ucsb-seclab/CVEX-v3/blob/main/REFERENCE_RECORDS.md)
and stored in [`ucsb-seclab/CVEX-records`](https://github.com/ucsb-seclab/CVEX-records):
CVE-2017-12617, CVE-2021-41773, and CVE-2015-1427. They illustrate the general
CVEX format, but your chosen CVE must meet the assignment-specific requirements
in §2, including remote exploitability.

Doing it by hand shows what the task really takes: which steps are
mechanical, and which need judgment no tool has yet.

---

## 1. Steps

1. **Learn the format.** Read the upstream design document and study the
   three reference records listed in `REFERENCE_RECORDS.md`. The records live
   in `ucsb-seclab/CVEX-records`; this assignment repository does not vendor
   local copies of them.
2. **Choose and claim a CVE** (§2).
3. **Build the record** (§3) and check it with the runner until it passes.
4. **Write the report** (§5).
5. **Push to `main`** before the deadline.

## 2. Choosing a CVE

Your CVE must:

- affect an **open-source project that is actively developed** at the time
  you choose the CVE. Cite the upstream repository, its open-source license,
  and evidence of ongoing development, such as recent commits or releases.
  The vulnerable version may be older than the current release;
- be **remotely exploitable**: an attacker must be able to trigger the
  vulnerability over a network through the affected software's interface,
  without already having local code execution or shell access on the target.
  Document any required authentication or other preconditions;
- **not already have a CVEX record**. Check the upstream
  [`EXISTING_RECORDS.txt`](https://github.com/ucsb-seclab/CVEX-v3/blob/main/EXISTING_RECORDS.txt)
  before you claim; the course preflight also carries a snapshot of this list
  in `.cs279/existing_records.txt`;
- **not be claimed by another student** (see below);
- **fit the format**: Docker only, no kernel or Windows vulnerabilities.
  The vulnerable software must be obtainable and
  vendorable into the record (note: this means that you can copy the
  software components into the record and not just refer to an external
  component);
- have **public information sufficient to reproduce it**, such as an
  advisory, a fix commit, or a published proof of concept;
- have a security impact that a **flag can witness**, using one of the
  placements in design document §2.2. Crash-only vulnerabilities (§2.3) are
  not acceptable.

**Claim it** by opening an issue with the *Claim a CVE* form in the
`cs279-f26/cve-claims` repository. A bot answers within minutes: *accepted*,
or *rejected* with the reason (already recorded, already claimed, malformed
ID). Claims are first come, first served. You may release a claim and pick
another CVE until the claim deadline. After it, changes need instructor
approval.

Pick something you can finish. A two-year-old web application with a clean
advisory is a better choice than a decade-old daemon whose build depends on
a vanished toolchain. Before you claim, spend an hour checking that you can
get the vulnerable version and build it.

## 3. What the record must satisfy

Your record follows the layout and rules of the design document (§1, §4,
§5, §7). In particular:

- **Uniform structure**: `cvex.yml`, `target/`, `benign/`, `attacker/`,
  `recorder/`, and the committed reference `dataset/`.
- **Remote reproduction.** Use `topology: target-attacker` or
  `topology: target+db-attacker`, with the attacker exercising the
  vulnerability over the network from a separate container. The benign
  client must also interact with the target over the network.
- **The real affected software.** The target runs the product and version
  named in the CVE, built from vendored sources or packages in
  `target/vendor/`. Configuration changes needed to expose the vulnerability
  must be ones a real deployment could have. Document each one in the
  report, with a source.
- **Offline target build**: `docker build --network none target/` succeeds.
  Base images are pinned by `@sha256` digest. In practice, this means that 
  your setup can be built without network access (implying that it has no
  external dependencies).
- **A sound flag gate.** The flag is placed so that the benign client and a
  legitimate user cannot read it, and only exercising this vulnerability
  reveals it. Never make the flag reachable by other means, such as
  weakening permissions or adding a helper.
- **No hard-coded flag outside the target.** The runner plants a fresh
  random flag on every run, so a client that embeds the committed value
  fails.
- **A meaningful benign client** that uses the same service, and where
  possible the same feature, in a legitimate way. Its run must complete
  successfully and must never see the flag.
- **A committed reference dataset** in `dataset/`, produced by the runner,
  with `verdict.json` reporting success.

The record must be your own work. You may adapt public proof-of-concept
material. If you do, credit it in the report and keep its license notice.

## 4. The course runner

The template repository includes the course runner, `.cs279/cvex.py`
(Python 3.10+, PyYAML, Docker with Compose v2). The grader uses the same
runner.

```bash
python3 .cs279/cvex.py check CVE-YYYY-NNNNN            # static checks: layout, manifest, pins, flag rules
python3 .cs279/cvex.py run   CVE-YYYY-NNNNN --fresh-flag --out /tmp/run1
python3 .cs279/cvex.py run   CVE-YYYY-NNNNN --out CVE-YYYY-NNNNN/dataset   # refresh the reference dataset
```

`run` follows the protocol of design document §6: a fresh target per phase,
the benign phase, then the attack phase, then verification. It writes the
dataset layout of §8 and a `verdict.json`. It exits with status 0 only if
the attack captured the planted flag and the benign phase never exposed it.

Syscall traces are truncated at 48 MiB per phase, because a JVM target can
trace hundreds of megabytes in a minute and GitHub refuses any file over
100 MB. When that happens the last record of the `.jsonl` says so and gives
the number of dropped lines, and the oversized raw `.log` is removed. Say in
your report if your trace was truncated.

## 5. The report

`REPORT.md`, which must describe the following:

1. **The vulnerability.** What it is and where it lives in the code. The
   affected and fixed versions, and what the fix changed. Cite the advisory
   and the fix. Provide evidence that the project is open source and actively
   developed, and explain the remote attack path and its preconditions.
2. **The record.** How the target is built and configured, and why each
   non-default setting is realistic. Where the flag is, and why only this
   vulnerability reaches it. What the benign client does, and why it is a fair
   counterpart to the attack.
3. **Provenance.** Where every vendored artifact and any reused code came
   from (URL, version, checksum, license).
4. **What it took.** The problems you met and how you solved them, how long
   the main steps took, and what would be hard to automate.

## 6. Repository layout

```text
submission.toml          assignment = "A02", members, record = "CVE-YYYY-NNNNN"
CVE-YYYY-NNNNN/          the record
REPORT.md
AI_USAGE.md
.cs279/                  course tools (do not modify)
```

Large vendored files are fine up to 100 MB per file (GitHub's limit). If the
vulnerable software is bigger, ask the instructors before you claim the CVE.

Feedback runs: **3 for the whole assignment** (see the submission guide, §4).

## 7. Grading

The grader runs `check`, builds the target offline, and runs the record
**three times** with a fresh flag each time.

| Criterion | Points | How |
|---|---:|---|
| `check` passes with no errors | 10 | automated |
| Target builds offline | 10 | automated |
| Attack captures the fresh flag: 3 of 3 runs → 25, 2 → 15, 1 → 8 | 25 | automated |
| Benign phase succeeds and never exposes the flag, in all runs | 10 | automated |
| **Fidelity**: the CVE affects an actively developed open-source project; the target is the affected product and version; the configuration is realistic and documented; the record exercises this CVE remotely rather than some other weakness; the flag gate is sound | 20 | AI-assessed |
| **Report**: correct, code-level explanation of the vulnerability and the fix; sound justification of the flag placement and the benign client; complete provenance | 15 | AI-assessed |
| **Engineering**: digest pins, a clean and minimal record, a coherent committed dataset, AI disclosure | 10 | AI-assessed |

A record that fails the fidelity check can lose the automated reproduction
points too: a flag captured from the wrong software proves nothing about
the CVE. Instructors check all fidelity scores below 10 before releasing
grades.

Records that pass with high fidelity may become candidates for the public
CVEX corpus, with credit to their author. Contributing is optional and
unrelated to your grade.
