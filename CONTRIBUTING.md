# Contributing

Start with [DEVELOPMENT.md](docs/DEVELOPMENT.md), then read the specification and the plan for the milestone you are changing. Small, reviewable changes, scrubbed hardware fixtures and clear rule explanations are welcome. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Enable the git hooks with `bash scripts/install-hooks.sh`. Before submitting, run `bash scripts/check.sh all`, which covers formatting, clippy, rustdoc, tests, `cargo deny`, the boundary checks in `scripts/` and the documentation, shell, Python and workflow linters described in [DEVELOPMENT.md](docs/DEVELOPMENT.md#validation). CI runs on Windows and Linux. Review changed snapshot files as terminal output, not just a passing test.

The no-write invariant is permanent. SSH commands may be defined only in `nm-collect/src/allowlist.rs`. Each addition needs the forbidden-verb check and approval by a reviewer other than its author. All socket creation belongs in `nm-collect/src/net.rs`. `nm-ai` must have no direct or indirect dependency on `nm-creds`. Never commit live credentials or unsanitized device output.

For an architectural decision, copy `docs/adr/0000-template.md` to the next numbered file, explain the context and consequences, and link it in the change. Declare new dependencies centrally in `[workspace.dependencies]`, inherit them in member manifests, regenerate `Cargo.lock` and run `cargo deny check`. Cargo's `cargo add` support for workspace inheritance varies; edit the workspace table directly when necessary. Contributions are licensed Apache-2.0 OR MIT.
