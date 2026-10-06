#!/usr/bin/env bash
# Claude Code PostToolUse hook: formats the file an agent just edited with the repository's
# formatter for its type. It never blocks the edit; scripts/check.sh and the git hooks enforce
# formatting. Files outside the repository or ignored by git (such as target/) are skipped.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 0

file="$(jq -r '.tool_input.file_path // empty' 2>/dev/null)" || exit 0
[[ -n "${file}" && -f "${file}" ]] || exit 0
[[ -n "$(git ls-files --cached --others --exclude-standard -- "${file}" 2>/dev/null)" ]] || exit 0

case "${file}" in
    *.rs)
        # rustfmt reads stdin so it formats only this file, not the modules it declares.
        command -v rustfmt >/dev/null || exit 0
        tmp="$(mktemp)"
        if rustfmt --edition 2021 --emit stdout <"${file}" >"${tmp}" 2>/dev/null && ! cmp -s "${tmp}" "${file}"; then
            cat "${tmp}" >"${file}"
        fi
        rm -f "${tmp}"
        ;;
    *.toml) command -v taplo >/dev/null && RUST_LOG=error taplo fmt "${file}" ;;
    *.py) command -v ruff >/dev/null && ruff format --quiet "${file}" ;;
    *.sh) command -v shfmt >/dev/null && shfmt --write "${file}" ;;
    *) ;;
esac
exit 0
