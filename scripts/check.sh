#!/usr/bin/env bash
# Static analysis and validation runner shared by the git hooks, CI and contributors.
#
#   bash scripts/check.sh [--staged] [--strict] [stage...]
#
# Stages (default: static):
#   static  fast checks that do not compile: whitespace, secrets, spelling, formatting,
#           shell/Python/Markdown/TOML/workflow lint, links, unused dependencies, socket boundary
#   rust    compiling checks: clippy, rustdoc, cargo-deny, AI credential boundary
#   test    cargo test for the whole workspace
#   all     static rust test
#
# --staged  limit file-based checks to files staged for commit (used by the pre-commit hook)
# --strict  fail when a tool is missing instead of skipping it (used by CI)
# SKIP=typos,clippy  skips the named checks for one run.
set -euo pipefail
cd "$(dirname "$0")/.."

staged=false
strict="${NM_STRICT:-false}"
stages=()
for arg in "$@"; do
    case "${arg}" in
        --staged) staged=true ;;
        --strict) strict=true ;;
        static | rust | test) stages+=("${arg}") ;;
        all) stages+=(static rust test) ;;
        -h | --help)
            sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: ${arg}" >&2
            exit 2
            ;;
    esac
done
[[ ${#stages[@]} -eq 0 ]] && stages=(static)

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    bold=$'\e[1m' red=$'\e[31m' green=$'\e[32m' yellow=$'\e[33m' reset=$'\e[0m'
else
    bold='' red='' green='' yellow='' reset=''
fi

failed=()
skipped=()

skip_requested() { [[ ",${SKIP:-}," == *",$1,"* ]]; }

# have TOOL: true when TOOL is on PATH; otherwise records a skip, or a failure under --strict.
have() {
    command -v "$1" >/dev/null 2>&1 && return 0
    if [[ "${strict}" == true ]]; then
        echo "${red}${bold}missing tool:${reset} $1 (see docs/DEVELOPMENT.md)"
        failed+=("$1 (missing)")
    else
        skipped+=("$1 (not installed)")
    fi
    return 1
}

# run NAME COMMAND...: runs one check, reports its duration and records the outcome.
run() {
    local name="$1"
    shift
    if skip_requested "${name}"; then
        skipped+=("${name} (SKIP)")
        return 0
    fi
    echo "${bold}==> ${name}${reset}"
    local start=${SECONDS}
    if "$@"; then
        echo "${green}ok${reset} ${name} ($((SECONDS - start))s)"
    else
        echo "${red}${bold}FAILED${reset} ${name}"
        failed+=("${name}")
    fi
}

# Files under consideration. In --staged mode only added/copied/modified/renamed index entries.
files=()
if [[ "${staged}" == true ]]; then
    mapfile -t files < <(git diff --cached --name-only --diff-filter=ACMR)
fi

# pick REGEX: prints considered files matching REGEX (staged mode only).
pick() { printf '%s\n' "${files[@]}" | grep -E "$1" || true; }

# wants REGEX: in full mode always true; in staged mode true when a staged file matches.
wants() { [[ "${staged}" == false ]] || [[ -n "$(pick "$1")" ]]; }

python_bin() {
    local candidate
    for candidate in python3 python; do
        # Skips the Windows Store alias, which exists on PATH but cannot run scripts.
        if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys' 2>/dev/null; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

# Runs COMMAND with the staged files matching REGEX appended, or with DEFAULT... in full mode.
#   with_files REGEX COMMAND... -- DEFAULT...
with_files() {
    local regex="$1"
    shift
    local cmd=()
    while [[ $# -gt 0 && "$1" != -- ]]; do
        cmd+=("$1")
        shift
    done
    shift
    if [[ "${staged}" == true ]]; then
        local selected=()
        mapfile -t selected < <(pick "${regex}")
        "${cmd[@]}" "${selected[@]}"
    else
        "${cmd[@]}" "$@"
    fi
}

empty_tree=4b825dc642cb6eb9a060e54bf8d69288fbee4904

stage_static() {
    if [[ "${staged}" == true ]]; then
        run whitespace git diff --cached --check -- . ':!*.snap'
    else
        run whitespace git diff --check "${empty_tree}" -- . ':!*.snap'
    fi

    if have gitleaks; then
        if [[ "${staged}" == true ]]; then
            run gitleaks gitleaks git --pre-commit --staged --redact --no-banner --log-level warn
        else
            run gitleaks gitleaks git --redact --no-banner --log-level warn
        fi
    fi

    if wants . && have typos; then
        run typos with_files . typos --force-exclude -- --
    fi

    if wants '\.rs$'; then
        if [[ "${staged}" == true ]]; then
            run rustfmt with_files '\.rs$' rustfmt --check --edition 2021 --
        else
            run rustfmt cargo fmt --all -- --check
        fi
    fi

    if wants '\.toml$' && have taplo; then
        run taplo with_files '\.toml$' env RUST_LOG=warn taplo fmt --check --colors never --
    fi

    if wants '\.sh$|^\.githooks/'; then
        local shell_files=()
        if [[ "${staged}" == true ]]; then
            mapfile -t shell_files < <(pick '\.sh$|^\.githooks/')
        else
            mapfile -t shell_files < <(git ls-files '*.sh' '.githooks/*')
        fi
        if have shellcheck; then run shellcheck shellcheck "${shell_files[@]}"; fi
        if have shfmt; then run shfmt shfmt --diff "${shell_files[@]}"; fi
    fi

    if wants '\.py$' && have ruff; then
        run ruff-lint with_files '\.py$' ruff check --force-exclude -- .
        run ruff-format with_files '\.py$' ruff format --check --force-exclude -- .
    fi

    if wants '\.md$'; then
        if have markdownlint-cli2; then
            run markdownlint with_files '\.md$' markdownlint-cli2 --no-globs -- '**/*.md'
        fi
        if have lychee; then
            run links with_files '\.md$' lychee --config lychee.toml -- .
        fi
    fi

    if wants '^\.github/'; then
        if have actionlint; then run actionlint actionlint; fi
        if have zizmor; then
            run zizmor zizmor --offline --no-progress --min-severity low .github/workflows
        fi
    fi

    if wants '(\.rs|Cargo\.toml)$' && have cargo-machete; then
        run unused-deps cargo machete
    fi

    if wants '\.rs$'; then
        run socket-boundary bash scripts/check-no-direct-connect.sh
    fi
}

stage_rust() {
    run clippy cargo clippy --locked --workspace --all-targets -- -D warnings
    run rustdoc env RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --quiet
    if have cargo-deny; then run cargo-deny cargo deny --log-level warn check; fi
    local python
    if python="$(python_bin)"; then
        run creds-boundary "${python}" scripts/check-dependency-boundaries.py
    else
        have python3 || true
    fi
}

stage_test() {
    run test env INSTA_UPDATE=no cargo test --locked --workspace --quiet
}

if [[ "${staged}" == true && ${#files[@]} -eq 0 ]]; then
    echo 'No staged files to check.'
    exit 0
fi

for stage in "${stages[@]}"; do
    "stage_${stage}"
done

echo
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "${yellow}Skipped:${reset} ${skipped[*]}"
fi
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "${red}${bold}Failed:${reset} ${failed[*]}"
    exit 1
fi
echo "${green}${bold}All checks passed.${reset}"
