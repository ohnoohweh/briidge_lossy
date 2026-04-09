#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
echo "Local git hooks enabled: core.hooksPath=.githooks"
echo "Pre-commit will now run:"
echo "  - python scripts/check_readme_testing_guard.py --staged"
echo "  - python scripts/check_requirements_guard.py --staged"
