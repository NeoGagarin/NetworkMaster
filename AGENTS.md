# Agent guide

Instructions for coding agents (Claude Code, Codex, Cursor and others) working in this repository. Humans should start with [CONTRIBUTING.md](CONTRIBUTING.md); everything here applies to them too.

NetworkMaster is a read-only network assessment tool for small ISPs and WISPs, written as a Rust workspace with a CLI, a terminal UI and (later) an MCP server over one shared application service. [docs/SPEC.md](docs/SPEC.md) is the source of truth. Work is organised into milestones in [docs/plans/](docs/plans/README.md); read the plan for the milestone you are touching before changing code, and follow its definition of done.

## Non-negotiables

These are SPEC §1.3 rules. Do not weaken them to make a task easier. If a task seems to require it, stop and ask, or write an ADR.

- **No write path to devices.** SSH commands are defined only in `crates/nm-collect/src/allowlist.rs`. Every addition must pass the forbidden-verb test and needs approval from a reviewer other than its author; never add one silently. HTTP is GET-only apart from the closed list of login endpoints.
- **Only enrolled devices are contacted.** All socket creation goes through `crates/nm-collect/src/net.rs` and the `TargetGate`. `scripts/check-no-direct-connect.sh` rejects `TcpStream::connect` or `UdpSocket::bind` anywhere else.
- **Credentials never reach AI.** `nm-ai` must not depend on `nm-creds`, directly or transitively. `deny.toml` and `scripts/check-dependency-boundaries.py` enforce this.
- **Every external action is audited**, and dry runs print the same sequence without executing it.
- **No telemetry or phone-home**, and no network access in tests. Tests run with `NETMASTER_NET=deny` where relevant.
- **Device data is untrusted model input.** Hostnames, SSIDs and comments are passed as structured data, never interpolated into prompts.
- **Never commit live credentials or unsanitized device output.** Fixtures must be scrubbed or explicitly synthetic. gitleaks runs on every commit.

`unsafe_code` is forbidden workspace-wide.

## Commands

All checks go through one script, which the git hooks and CI also call. Run it from Git Bash on Windows.

```text
bash scripts/check.sh            # static checks, a few seconds, no compilation
bash scripts/check.sh rust       # clippy -D warnings, rustdoc -D warnings, cargo-deny, credential boundary
bash scripts/check.sh test       # cargo test --locked --workspace
bash scripts/check.sh all        # everything; run this before you report a task as done
SKIP=clippy,test bash scripts/check.sh all
```

Build and run with `cargo build --locked --workspace` and `cargo run -p nm-cli --` (the binary is `netmaster`). [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) lists every check, its tool and its configuration file, and [docs/CLI.md](docs/CLI.md) documents the command tree and exit codes.

## Hooks

- **Git:** `bash scripts/install-hooks.sh` points `core.hooksPath` at `.githooks/`. pre-commit runs the static checks on staged files; pre-push runs `check.sh all`. Do not bypass them with `--no-verify` unless the user asks; if a hook fails, fix the cause.
- **Claude Code:** `.claude/settings.json` runs `.claude/hooks/format.sh` after every Edit or Write. It formats the edited file with rustfmt, taplo, ruff or shfmt, so expect the file to change after you write it and re-read it before a follow-up edit.

## Conventions

- Declare dependencies once in the root `[workspace.dependencies]` and inherit them with `dep.workspace = true`. Run `cargo deny check` after any lockfile change. Unused dependencies fail cargo-machete.
- Clippy runs with `pedantic` as errors. Fix lints rather than adding `allow` attributes; when an allow is truly needed, scope it narrowly and give a reason.
- Public items need doc comments; rustdoc warnings are errors.
- Terminal UI and parser output use insta snapshots. Never accept snapshot changes blindly. Inspect the rendered output, then update with `INSTA_UPDATE=always` and rerun without it. Do not commit `*.snap.new` files.
- Architectural decisions get an ADR: copy `docs/adr/0000-template.md` to the next number.
- Add a `CHANGELOG.md` entry under `Unreleased` for user-visible changes.
- Text files use LF line endings (`.gitattributes`). Markdown is one paragraph per line; fenced code blocks need a language (`text` if nothing else applies).
- Commit messages use a short imperative subject (`Add SSH host key pinning`) and a body that explains why.

## Working alongside other agents

Several agents may share this checkout. Before you edit, run `git status` and treat changes you did not make as someone else's work in progress. Do not revert, reformat, stash or commit them. When your task touches files that are already modified, work in a separate worktree or branch, or ask the user first. Stage files by path (`git add <path>`), never with `git add -A` or `git commit -a`.
