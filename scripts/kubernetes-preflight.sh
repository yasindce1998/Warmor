#!/usr/bin/env bash
# Read-only bounded diagnostics; no installs, BPF attachment, signaling or writes.
# Run in the ACTUAL agent security context or directly on an isolated node.
set -euo pipefail
CGROUP_ROOT="${WARMOR_CGROUP_ROOT:-/sys/fs/cgroup}"
KERNEL_ROOT="${WARMOR_KERNEL_ROOT:-/sys/kernel}"
PROC_ROOT="${WARMOR_PROC_ROOT:-/proc}"
read_if_present() {
  local label="$1" path="$2"
  echo "$label ($path):"
  if [[ -r "$path" ]]; then head -c 4096 "$path"; echo
  else echo "  unavailable (missing or permission denied)"; fi
}
echo "Read-only Warmor Linux preflight; NOT proof of enforcement support"
uname -srm
read_if_present "Kernel LSM list" "$KERNEL_ROOT/security/lsm"
if [[ -r "$KERNEL_ROOT/btf/vmlinux" ]]; then echo "BTF: readable"; else echo "BTF: unavailable"; fi
if [[ -r "$CGROUP_ROOT/cgroup.controllers" ]]; then
  read_if_present "cgroup v2 controllers" "$CGROUP_ROOT/cgroup.controllers"
else echo "cgroup v2: NOT confirmed at $CGROUP_ROOT"; fi
for hierarchy in kubepods.slice kubepods; do
  if [[ -d "$CGROUP_ROOT/$hierarchy" ]]; then echo "Pod hierarchy visible: $CGROUP_ROOT/$hierarchy"; fi
done
read_if_present "Self cgroup namespace path" "$PROC_ROOT/self/cgroup"
echo "Effective credentials/capabilities (inspect in the agent container):"
grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' "$PROC_ROOT/self/status" || true
echo "Namespace identities (compare agent and node PID 1):"
for pid in self 1; do
  for namespace in pid cgroup mnt user; do
    target=$(readlink "$PROC_ROOT/$pid/ns/$namespace" 2>/dev/null || true)
    echo "  $pid/$namespace: ${target:-unavailable}"
  done
done
read_if_present "IMA policy" "$KERNEL_ROOT/security/ima/policy"
echo "Bounded mount visibility (first 40 matching lines):"
awk '/cgroup|\/sys\/kernel|\/proc / {if (++n<=40) print}' "$PROC_ROOT/self/mountinfo" || true
echo "Next: isolated capability/hook/CNI tests in deploy/helm/warmor/README.md"
