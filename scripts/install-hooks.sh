#!/usr/bin/env bash
# Installs the WitSeal git hooks for this repository (local config only).
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git config core.hooksPath .githooks
chmod +x .githooks/commit-msg

echo "Installed: local core.hooksPath -> .githooks"
echo "Active hooks: commit-msg (deferred (locked) vocabulary rejection)"
