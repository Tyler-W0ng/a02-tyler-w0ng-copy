# CS279 assignment repository

The assignment handout is `HANDOUT.md`; `SUBMISSION.md` explains how to
work on and submit every assignment. Read both first. Work on `main`; the last
commit pushed to `main` before the deadline is your submission. Every push
runs a preflight check (Actions tab); run it locally with

    python3 .cs279/preflight.py

To request a feedback run, push a tag whose name starts with `feedback`:

    git tag feedback-1 && git push origin feedback-1

In assignments built on AgentLab, `AGENTLAB.md` is AgentLab's own README:
how to run the stack, the gateway, the knowledge base, and tracing.

`.cs279/` holds the course tools. Do not modify it: the grader uses its own copy.
