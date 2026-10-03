#!/usr/bin/env bash
# Build garmr-server and OPA, then benchmark both end to end.
#
#   scripts/bench-e2e/run.sh            # full run (~40 min)
#   scripts/bench-e2e/run.sh -quick     # smoke run
#   scripts/bench-e2e/run.sh -phases verify,closed -servers garmr
#
# Servers are pinned to CPUs 0-3 (GOMAXPROCS=4) and the load generator to
# 4-7 so they do not compete; override with BENCH_SERVER_CPUS /
# BENCH_CLIENT_CPUS. For stable numbers set the performance governor first:
#   sudo cpupower frequency-set -g performance
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
opa_version="${OPA_VERSION:-v1.21.1}" # keep in step with scripts/bench-opa/go.mod

make -C "$root" build-server >/dev/null
mkdir -p "$here/bin"
if ! "$here/bin/opa" version 2>/dev/null | grep -q "^Version: ${opa_version#v}$"; then
	echo "building opa $opa_version"
	GOBIN="$here/bin" go install "github.com/open-policy-agent/opa@$opa_version"
fi
(cd "$here" && go build -o bin/bench-e2e .)

cd "$here"
exec taskset -c "${BENCH_CLIENT_CPUS:-4-7}" ./bin/bench-e2e \
	-garmr "$root/bin/garmr-server" -opa "$here/bin/opa" \
	-server-cpus "${BENCH_SERVER_CPUS:-0-3}" "$@"
