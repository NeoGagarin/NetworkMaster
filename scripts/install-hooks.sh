#!/usr/bin/env bash
# Points this clone at the versioned hooks in .githooks. Undo with `git config --unset core.hooksPath`.
set -euo pipefail
cd "$(dirname "$0")/.."
git config core.hooksPath .githooks
echo 'Git hooks enabled: pre-commit (staged static checks) and pre-push (full validation).'
