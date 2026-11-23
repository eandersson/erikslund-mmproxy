#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

export MSYS_NO_PATHCONV=1

case "${1:-test}" in
    build|test|clang-tidy|cppcheck|hardening)
        docker compose run --rm -T --build --no-deps dev bash /workspace/scripts/check.sh "${1:-test}"
        ;;
    *)
        echo "Usage: bash scripts/dev.sh [build|test|clang-tidy|cppcheck|hardening]" >&2
        exit 2
        ;;
esac
