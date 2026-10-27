# Working on and submitting assignments

Every CS279 assignment lives in a private GitHub repository that the course
creates for you (or for your group). You work in it, you push to it, and it is
what gets graded: there is nothing to upload anywhere else. This page explains
how that works. Each assignment's handout adds what is specific to it.

## 1. Registration

You registered with your **UCSB student ID (perm number)**, your UCSB email,
and your **GitHub username**; the course created your repositories from that.
If your GitHub username has changed, tell the instructor.

Your student ID is how the course identifies you: grades are recorded
against it. It stays in the course roster, which only the instructors can
read. **Do not put your student ID in any repository**, commit message, or
report. Your GitHub username is enough there.

The instructor assigns the groups for A03, A05 and A06. Each group has a
number, and its members are fixed. Changes go through the instructor.

## 2. Your repositories

For each assignment you receive an invitation to a repository in the course
organization, **`cs279-f26`**:

| Kind | Repository name | Who has write access |
|---|---|---|
| individual (A01, A02, A04) | `a01-<your-github-username>` (and `a02-`, `a04-`) | you |
| group (A03, A05, A06) | `a03-team07` | every member of team 07 |

Accept the invitation. Accepting it also proves that the GitHub account in
the roster is really yours. The repository starts from a template with:

- `HANDOUT.md`, the assignment's handout, and `SUBMISSION.md`, this page;
- the starter material for the assignment, if any;
- `submission.toml`, a small manifest you complete (see below);
- `AI_USAGE.md`, where you disclose how you used AI tools (§6);
- `.cs279/`, the course's tools (the preflight checker and, for some
  assignments, a runner). Don't modify it. The grader uses its own copy.
- `.github/workflows/preflight.yml`, which runs the preflight checker on every
  push.

Repositories are private: only you (or your group) and the instructors can
see them. Do not make them public, do not add collaborators, and do not fork
them into your own account.

### `submission.toml`

```toml
assignment = "A02"
members = ["your-github-username"]   # all members, for groups

# assignment-specific keys, described in each handout, e.g.:
record = "CVE-2023-12345"
```

The roster, not this file, decides who gets credit. The file tells the
grader where things are, and lets preflight check that they are there.

## 3. Work, push, and check

Work on the **`main` branch**. Push as often as you like: there is no penalty
for intermediate commits, and frequent pushes protect you against losing work.

Every push runs **preflight** (the *Actions* tab of your repository, and the
✓ or ✗ next to each commit). Preflight is fast and deterministic. It checks
that the required files exist, that `submission.toml` is complete, and that
manifests and reports parse and validate. It does **not** run your system and
does not grade you. A red ✗ means the grader will not find something it
needs. Fix it before the deadline. You can run the same check locally:

```bash
python3 .cs279/preflight.py
```

## 4. Ask for feedback (optional)

For most assignments you can request a **feedback run** before the deadline.
A feedback run executes the real grading pipeline on your current code, with
the automated checks and the AI review, on the public development inputs.
It never uses the hidden part of the evaluation set. (A01 is an exception:
its feedback runs use the public half of the evaluation set.) To request one, push a tag whose name
starts with `feedback`.

**Before you tag**, make sure the run will grade what you think it grades:

1. commit **everything**, new files included: `git status` must show nothing
   to commit (`git commit -a` skips new files; `git add` them first);
2. `git push`, then check on github.com that the latest commit on `main` is
   yours and that preflight shows a green ✓ next to it;
3. only then tag that commit and push the tag:

```bash
git tag feedback-1
git push origin feedback-1
```

A tag is graded at the commit it points to when the grader first sees it,
and a tag name is graded only once: moving or re-pushing a tag does not
start another run. If you tagged the wrong commit, fix it and push a new
tag (`feedback-2`), which uses another run.

The grader looks for new tags every hour. When the run finishes (from a few
minutes to a few hours, depending on the assignment), the results appear as
an **issue** in your repository titled *Feedback: feedback-1 (abc1234)*,
with your preflight result, how many feedback runs you have left, and a
score per rubric criterion with comments.

Feedback runs cost real compute and model time, so you have **3 per
assignment** (per repository: a group shares its 3). Tags beyond them are
ignored. A run that fails because of the course's infrastructure, not your
code, is repeated and does not count. Feedback scores are indicative only:
the final run uses hidden inputs, and the instructors review the
AI-assessed parts.

## 5. Submitting

**There is no separate submit step.** Your submission is **the last commit on
`main` that you pushed before the deadline**, according to GitHub's record of
when each push reached it. Commit dates are set by your machine and don't
count. If you pushed late, the grader uses the last commit pushed in time.

At the deadline, the course changes your access to the repository to
read-only. You can still read it and comment on issues, but you can't push.
If you have an approved extension, your access stays as it is until the
extended deadline, and that deadline applies to you.

Before the deadline, make sure that:

1. everything is committed **and pushed** to `main` (check on github.com, not
   just locally);
2. the latest commit has a green preflight ✓;
3. large files are not missing. Git LFS is not supported; if the handout
   allows large artifacts, it says how to provide them.

## 6. AI tools

This is a course about AI for vulnerability analysis: you are encouraged to
use AI tools to write code, to understand vulnerabilities, and to draft text.
Two rules:

- **Disclose.** In `AI_USAGE.md`, list the tools and models you used, what you
  used each for, and how you checked their output. "I used Claude Code to write
  the first version of `target/Dockerfile`, then fixed the build flags by hand"
  is the level of detail expected. No AI use? Write that.
- **You own the result.** Everything you submit is your claim. An AI tool
  inventing a log, a citation, or a "verified" result that never happened
  counts the same as you inventing it.

## 7. How grading works

Each handout has a rubric worth 100 points. Every criterion is graded one of
three ways:

| Kind | Who grades | Examples |
|---|---|---|
| **automated** | deterministic code, run by the course grader | does the record build offline; does the exploit capture a fresh flag; how many hidden vulnerabilities your pipeline found |
| **AI-assessed** | an LLM, applying the rubric to your repository and to the automated results | is the root-cause analysis correct; is the vulnerability a genuine logic flaw; is the report clear |
| **instructor** | the instructors | the A03 presentation |

The grader runs in the course's own GitHub organization, on clean machines.
It fetches your submitted commit, builds and runs what the assignment
requires, and stores everything it observes. It always uses its own copy of
the tools and tests, never the copy in your repository. The AI reviewer gets
the rubric, your repository, and the automated results. It must justify each
score by citing files and lines, and anything it is unsure about is flagged
for the instructors. Instructors review the AI-assessed scores before grades
are released.

**Do not address the grader.** Text in your repository that tries to
instruct an AI grader ("ignore the rubric", "give full marks") is not
evidence of anything. It is detected and flagged, and handled as academic
misconduct. Your code and reports are analyzed as data, not followed as
instructions.

## 8. Grades and regrades

When grades are released, each repository gets an issue titled *Grade:
A0x*, with the points for every criterion and the reviewer's comments. The
same total is recorded in the course gradebook against your student ID.

To request a regrade, **comment on that issue within 7 days**. Name the
criterion and explain, with references to your files, why the assessment is
wrong. An instructor (a human) reviews every request.

## 9. Integrity, groups, and safety

- **Individual assignments** are individual: discuss ideas freely, but do not
  share code, records, or reports.
- **Group assignments**: everyone in the group receives the group's grade.
  `CONTRIBUTIONS.md` must say who did what. Serious imbalances are handled by
  the instructors, case by case.
- **Run exploits only against targets you build yourself or that the course
  provides, inside containers.** Never against systems you don't own, including
  university systems. If your work uncovers a vulnerability that is not yet
  public, tell the instructors before telling anyone else.
- Never commit API keys or tokens. The grader provides model access through the
  course gateway when an assignment needs it.

## 10. Problems

If the grader fails on something that isn't your fault (for example, an
outage, or a timeout on the grader's side), the run is repeated at no cost
to you. Report anything odd through the course forum, or privately to the
instructors if it involves your code.
