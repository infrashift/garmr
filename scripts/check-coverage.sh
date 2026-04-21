#!/usr/bin/env bash
# scripts/check-coverage.sh
#
# Measures statement coverage across the CLI↔server integration surface:
#   - cmd/garmr (CLI)
#   - internal/client (REST client)
#   - internal/server (HTTP server)
#
# Excludes helpers that are explicitly out of scope per project memory:
#   - cmd/garmr/docs_cmd.go   (static documentation generator)
#   - cmd/garmr/test_cmd.go   (policy test-harness command)
#
# Fails if total coverage drops below MIN_COVERAGE (default 83, target 90).

set -euo pipefail

MIN_COVERAGE="${MIN_COVERAGE:-90}"
TARGET_COVERAGE=90

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PROFILE="$WORK_DIR/coverage.out"
FILTERED="$WORK_DIR/coverage.filtered.out"

echo "==> Running tests with coverage on CLI↔server surface..."
go test -short -coverprofile="$PROFILE" -covermode=atomic \
  ./cmd/garmr/... \
  ./internal/client/... \
  ./internal/server/...

# Preserve the mode header, strip out-of-scope files.
(
  head -n 1 "$PROFILE"
  tail -n +2 "$PROFILE" | grep -v -E 'cmd/garmr/(docs_cmd|test_cmd)\.go'
) > "$FILTERED"

TOTAL=$(go tool cover -func="$FILTERED" | awk '/^total:/ { gsub("%","",$3); print $3 }')

echo "==> Integration surface coverage: ${TOTAL}% (floor ${MIN_COVERAGE}%, target ${TARGET_COVERAGE}%)"

# Bash float compare via awk.
if awk "BEGIN { exit !($TOTAL < $MIN_COVERAGE) }"; then
  echo "ERROR: coverage ${TOTAL}% is below the minimum ${MIN_COVERAGE}%." >&2
  exit 1
fi

