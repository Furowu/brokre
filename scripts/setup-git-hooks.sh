#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

chmod +x .githooks/prepare-commit-msg
git config core.hooksPath .githooks

echo "Git hooks enabled: core.hooksPath=.githooks"
