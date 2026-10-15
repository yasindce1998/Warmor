# BPF / Kernel Compatibility

Warmor's enforcement layer is BPF-LSM programs loaded into the running kernel.
Because those programs read kernel-internal structures, kernel-version
portability is the single most important reliability property of the project.
This document describes how that portability is achieved, what the kernel must
provide, and which kernels are tested.

## How portability works (CO-RE)

The kernel structs we read (`linux_binprm`, `dentry`, `socket`, `sock`,
`task_struct`, …) are not part of any userspace header, and their field offsets
differ between kernel versions and configs. We rely on **CO-RE** (Compile Once –
Run Everywhere):

- `bpf/vmlinux.h` provides the full set of kernel type definitions (generated
  from a 6.19 kernel's BTF), each struct tagged
  `__attribute__((preserve_access_index))`.
- At load time, `cilium/ebpf` reads the running kernel's own BTF
  (`/sys/kernel/btf/vmlinux`) and **relocates** every field access to the
  correct offset for that kernel.

This means a single compiled `.o` runs across kernels — *provided the field
actually exists in the running kernel's BTF*.

### Rule: read nested fields with `BPF_CORE_READ`, never copy whole structs

CO-RE relocates the offset of a field, but it does **not** rewrite the *layout*
of a struct we copy wholesale. If we declare a partial struct and
`bpf_probe_read` the whole thing, our layout assumption can disagree with the
kernel's and we read garbage.

Concretely, this bit us with `struct qstr` (the `d_name` of a dentry): copying
the struct assumed a layout that did not hold on all kernels. The fix — and the
standing rule — is to walk pointers field-by-field:

```c
// Good: each step is individually relocated by CO-RE.
const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

// Avoid: copies a struct whose full layout we don't actually control.
struct qstr q;
bpf_probe_read_kernel(&q, sizeof(q), &dentry->d_name);
```

When adding a hook that reaches into a new struct, the types are already
available in `vmlinux.h` — just access them with `BPF_CORE_READ`.

To regenerate `vmlinux.h` from a running kernel (e.g. after a major version bump):

```sh
cd bpf && make gen-vmlinux
```

## Kernel requirements

| Requirement | Why | How to check |
|---|---|---|
| Linux ≥ 5.7 (5.8+ recommended) | `lsm/*` attach type; ring buffer maps land in 5.8 | `uname -r` |
| `CONFIG_BPF_LSM=y` | enables BPF programs on LSM hooks | `zgrep BPF_LSM /proc/config.gz` |
| `bpf` in the active LSM list | the BPF LSM must be enabled at boot | `cat /sys/kernel/security/lsm` |
| `CONFIG_DEBUG_INFO_BTF=y` | CO-RE relocations need kernel BTF | `ls /sys/kernel/btf/vmlinux` |

If `bpf` is not in `/sys/kernel/security/lsm`, add it via the kernel command
line, e.g. `lsm=lockdown,capability,...,bpf`.

Warmor checks these at startup:

- `IsLSMSupported()` verifies `bpf` is in the active LSM list. It reads
  `/sys/kernel/security/lsm` first, then falls back to parsing the `lsm=`
  parameter in `/proc/cmdline` (needed on WSL2 where securityfs is not
  auto-mounted).
- `LoadLSM()` verifies `/sys/kernel/btf/vmlinux` exists and returns an
  actionable error (rather than an opaque verifier failure) if BTF is missing.

What happens when a requirement is unmet depends on the startup posture — see
[SECURITY_POSTURE.md](SECURITY_POSTURE.md). By default Warmor degrades to
observe-only; `--require-lsm` makes any of these failures fatal.

## Tested kernel matrix

CI (`.github/workflows/lsm-test.yml`) loads and exercises every LSM program in
a VM (via [vimto](https://lmb.io/vimto)) across multiple kernels, using
[`cilium/ci-kernels`](https://github.com/cilium/ci-kernels) `-selftests` images.
The `-selftests` config is the one built with `CONFIG_BPF_LSM=y` and BTF, and
upstream only builds it for the three release **channels** — not for the numeric
version tags (`5.15`, `6.1`, …), which ship without BPF LSM. So these three are
the only BPF-LSM-capable images available off the shelf:

| Channel | Role | Approx. version | Blocking |
|---|---|---|---|
| `longterm-selftests` | oldest of the three | ~6.18 | yes |
| `stable-selftests` | current stable — the primary gate | ~6.19 | yes |
| `mainline-selftests` | newest / release-candidate — early warning | ~7.0 | no (`continue-on-error`) |

`fail-fast` is disabled so one kernel's failure doesn't mask the others.
`mainline` is allowed to fail because bleeding-edge kernels churn; a red
`mainline` is a heads-up to investigate before it reaches `stable`, not a merge
blocker.

Two more kernels are built in CI from the ci-kernels configuration plus IMA
(`ci/kernel/`, `scripts/build-ci-kernel.sh`): **6.18** (current longterm) and
**6.1** (the oldest LTS the BPF programs target). The whole LSM suite runs on
them with the exec integrity tests required. 6.1 is where struct layouts
differ most from the committed `vmlinux.h`, so it is the main CO-RE check.
5.10 and 5.15 are not tested yet; adding a version is one matrix entry in
`.github/workflows/lsm-test.yml`.

To reproduce a single kernel locally:

```sh
go install lmb.io/vimto@latest
# generate real bpf2go bindings first (see the CI "Generate BPF bindings" step)
vimto -kernel ghcr.io/cilium/ci-kernels:stable-selftests -- \
  go test -v -count 1 -tags integration ./internal/ebpf/

# Or on an IMA-enabled LTS kernel, with the integrity tests required
# (vimto needs an absolute kernel path):
scripts/build-ci-kernel.sh 6.1.188 /tmp/kernel-6.1
WARMOR_REQUIRE_IMA=1 vimto -kernel /tmp/kernel-6.1/vmlinuz -- \
  go test -v -count 1 -tags integration ./internal/ebpf/
```

## Known risks / limitations

- **`vmlinux.h` is generated from a single kernel version (6.19).** Fields
  removed in older kernels will fail CO-RE relocation at load time. Mitigation:
  only access fields via `BPF_CORE_READ` (which gracefully fails relocation) +
  the kernel matrix above.
- **5.10 and 5.15 are not tested yet.** The matrix covers 6.1, 6.18 and the
  ci-kernels channels (~6.18–7.3). Adding an older version to the IMA kernel
  matrix is the remaining coverage gap.
- **Policy matching is exact-hash (FNV-1a).** No prefix/glob matching, and hash
  collisions are theoretically possible. This is an architectural property of
  the current policy map, not a kernel-compat issue — noted here for awareness.
