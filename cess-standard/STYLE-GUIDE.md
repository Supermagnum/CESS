# CESS style guide (AI-assisted and human contributors)

This document is the **authoritative** guide for **how** changes are made: scope, style, tooling, and review expectations. It applies equally to contributors using AI assistants (Claude Code, Cursor, Copilot, and similar) and to humans working without them.

**Governance** (review rules, patents, algorithm registry) remains in [`CONTRIBUTING.md`](CONTRIBUTING.md). When this guide and `CONTRIBUTING.md` overlap, both apply; where they conflict on process, `CONTRIBUTING.md` wins.

---

## 1. Scope and discipline

- **One task, one change set.** Implement what was asked. Do not expand scope with drive-by refactors, cosmetic renames, or unrelated file edits.
- **Minimal diff.** Prefer a small, reviewable change that solves the problem over a large cleanup that also solves it.
- **Read before writing.** Inspect surrounding code, naming, types, imports, and documentation level. New code should read as if the same author wrote it.
- **Reuse.** Extend existing helpers, patterns, and vector formats instead of introducing parallel conventions.
- **Root causes.** Fix the underlying issue; avoid accumulating workarounds or duplicate “just in case” paths unless the spec requires them.

---

## 2. Prose, comments, and commits

- **Professional tone.** Clear, direct sentences. No filler, engagement bait, or telegraphic bullet chains where prose is clearer.
- **No emojis** in code, comments, commit messages, documentation, or machine-oriented strings.
- **Commits.** Use complete sentences in the imperative or descriptive style the project already uses. Explain what changed and why, not only identifiers.
- **Do not commit or push** to shared remotes (GitHub, GitLab, and similar) unless the repository maintainer has asked you to do so for that change.

---

## 3. Documentation and markdown

- **Do not** add or expand markdown files (README sections, guides, reports) unless the task explicitly calls for documentation or the maintainer agreed to it.
- **Investigation reports** (long exploratory write-ups, audit-style dossiers) MUST NOT be added without explicit permission from maintainers.
- When documentation is required: match existing structure; prefer linking to specs and `CONTRIBUTING.md` over duplicating normative rules.
- **Citations** in technical text: use normal markdown links for URLs; use code fences and file paths as the project already does.

---

## 4. Code (general)

- **Languages.** Follow each language’s usual formatting for the repo (Rust edition, Python version, and so on). Match existing `rustfmt` / formatter usage if present.
- **Comments.** Only where they disambiguate non-obvious intent, invariants, or security-relevant behaviour. Avoid commenting the obvious.
- **Error handling.** Prefer clear, unified control flow. Avoid deep nests of defensive `try`/`except` (or equivalent) unless the spec or environment demands it.
- **Unsafe code.** Forbidden unless the task explicitly allows it and maintainers require it; the conformance runner and related tools use `#![forbid(unsafe_code)]` where stated.

---

## 5. Cryptography and conformance artefacts

- **Exclusion list.** Respect the CESS cryptographic exclusion list and runner constraints described in [`CONTRIBUTING.md`](CONTRIBUTING.md). Do not wire excluded primitives into protocol verification paths.
- **Test vectors.** Hex in lowercase unless a format requires otherwise. Deterministic values only; no `TODO` placeholders in normative vectors.
- **Vendored test data.** Record **source**, **license**, and **canonical location** (RFC section, file name, upstream URL) in the artefact or an adjacent comment/TOML header.
- **Dependencies.** Before adding crates or Python packages, check transitive use of excluded algorithms and document the rationale in the change description if non-obvious.

---

## 6. AI-assisted workflow (tool-agnostic)

These rules apply no matter which AI product is used.

- **Instructions.** Follow user, project, tool, and skill instructions completely. If a skill file exists for the task, read it and follow it rather than improvising.
- **Truthfulness.** Do not claim tests passed or builds succeeded without actually running them when the task requires verification.
- **Context.** Treat the conversation as one thread: later messages refine the same task unless the user clearly starts a new one.
- **Output.** Prefer edits in the repository over pasted-only instructions when the environment allows running commands and applying patches.
- **Secrets.** Never commit keys, tokens, passwords, or personal data. Use placeholders and environment variables as the project does.

---

## 7. Human review expectations

- **Reviewability.** Keep commits logically grouped; separate mechanical edits from semantic edits when it helps reviewers.
- **Describe changes.** Pull/merge request descriptions should state intent, scope, and any spec or compatibility impact in full sentences.
- **Breaking changes.** Call them out explicitly and point to migration notes or version bumps if applicable.

---

## 8. When in doubt

- Prefer **asking** the maintainer over guessing when requirements are ambiguous or the change touches normative spec text.
- Prefer **existing** project files and patterns over introducing new top-level documents or new conventions.

---

## Revision

Maintainers may update this guide. Significant changes should be mentioned in the project changelog or release notes if the project uses them.
