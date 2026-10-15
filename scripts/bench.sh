#!/usr/bin/env bash
# Run the userspace performance harness (docs/PERFORMANCE.md) and keep the
# raw output in $OUT (default: bench-results/).
#
#   scripts/bench.sh            # everything (about 20 minutes)
#   QUICK=1 scripts/bench.sh    # short smoke run (CI): small iteration counts
#
# Summarise the repeated runs with scripts/bench-summary.py bench-results/*.txt
#
# The YAML policy needs cargo and the wasm32-unknown-unknown target; the
# Rust crate policy needs scripts/build-rust-policies.sh. Policies whose
# toolchain or artifact is missing are skipped with a message.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
out="${OUT:-$root/bench-results}"
mkdir -p "$out"

iters=200000x
count=5      # latency/throughput repetitions
load_count=3 # sustained-load repetitions, each in its own process
load_seconds=10
rates=(1000 10000 50000 0)
if [[ -n "${QUICK:-}" ]]; then
	iters=2000x
	count=1
	load_count=1
	load_seconds=1
	rates=(1000 0)
fi

{
	echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "commit:  $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	echo "go:      $(go version)"
	echo "kernel:  $(uname -sr)"
	echo "cpu:     $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
	echo "cores:   $(nproc) logical"
	echo "memory:  $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
	echo "load:    $(cut -d' ' -f1-3 /proc/loadavg) (1/5/15 min load average before the run)"
} | tee "$out/env.txt"

echo "==> decision latency and throughput"
go test -run '^$' -bench 'TimerOverhead|DecisionLatency|DecisionThroughputParallel' \
	-benchtime "$iters" -count "$count" ./internal/enforcer/ | tee "$out/latency.txt"

echo "==> cache hit rate (workload stream)"
go test -run '^$' -bench 'WorkloadStream' -benchtime "$iters" -count "$count" -v ./internal/enforcer/ |
	grep -v '^=== RUN' | tee "$out/workload.txt"

echo "==> lineage tracker"
go test -run '^$' -bench 'RecordExec' -benchtime "$iters" -count "$count" ./internal/lineage/ | tee "$out/lineage.txt"

# Each sustained-load run is its own process: RSS is per process and the Go
# runtime keeps freed memory mapped for a while.
echo "==> sustained load (${load_seconds}s per run)"
: >"$out/load.txt"
for policy in none fixture yaml rust-advanced; do
	for rate in "${rates[@]}"; do
		for _ in $(seq "$load_count"); do
			WARMOR_BENCH_LOAD_SECONDS="$load_seconds" go test -run '^$' \
				-bench "^BenchmarkSustainedLoad\$/^${policy}\$/^rate=${rate}\$" \
				-benchtime 1x ./internal/enforcer/ | grep -E '^Benchmark|SKIP' | tee -a "$out/load.txt" || true
		done
	done
done

echo "load:    $(cut -d' ' -f1-3 /proc/loadavg) (after the run)" | tee -a "$out/env.txt"
echo "==> results in $out (summarise with scripts/bench-summary.py $out/*.txt)"
