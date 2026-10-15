# Supply Chain Integrity

> **Status: Shipped (requires `CONFIG_IMA`).** CI builds IMA-enabled 6.1 and 6.18 kernels (`ci/kernel/`) and runs the integrity VM tests on them with skipping disabled: allow/deny by content, cache invalidation on modify, allowlist revocation, audit events, and overlayfs. Start in `audit` mode before `enforce`. See [Feature Status](STATUS.md).

Warmor can refuse to execute any binary whose **content** is not in an allowlist of known-good SHA-256 digests. Matching is on content, not path, so it catches:
- a binary that was modified after the image was built;
- a binary dropped into the container after it started (e.g. into `/tmp`);
- a `memfd` exec.

It does not matter where the file lives or what it is called.

## How it works

1. `warmor-integrity-scan` hashes the executables in an image rootfs into a JSON database.
2. `warmor-daemon --integrity-db <db> --integrity-mode audit|enforce` loads every distinct digest into the kernel map `integrity_allow`.
3. The sleepable LSM program `lsm.s/bprm_check_security` (`bpf/lsm_integrity.bpf.c`) hashes the file about to be executed with `bpf_ima_file_hash`. If the SHA-256 is not allowlisted:
   - **enforce:** the exec fails with `EPERM`. The event is recorded as a kernel deny, and nothing is killed, because the exec never happened.
   - **audit:** the exec proceeds, and a would-deny is reported.

Verdicts are cached per inode and re-checked when the file's ctime or size changes, or when the allowlist is replaced. A file IMA cannot hash is refused (fail closed).

The check covers whatever the kernel execs: ELF binaries, and scripts run directly (`./script.sh`), whose interpreter is checked too. It does **not** cover:
- shared libraries loaded with `mmap`;
- a script passed as an argument (`sh script.sh`), because only `sh` is exec'd;
- code loaded by an interpreter at runtime.

Scope follows `--cgroup-filter`. With no filter, every exec on the host is checked, so the allowlist must then cover the host's binaries too.

## Requirements

- BPF LSM (`bpf` in `/sys/kernel/security/lsm`), as for the rest of Warmor's kernel enforcement.
- **`CONFIG_IMA=y`.** Without it, `bpf_ima_file_hash` cannot hash anything. The daemon checks the kernel BTF at startup and refuses to enable integrity with a clear error rather than refusing every exec. Ubuntu, Debian, RHEL and Fedora kernels enable IMA.
- **IMA's hash algorithm must be SHA-256.** This is the default on major distributions; otherwise boot with `ima_hash=sha256`. No IMA policy is needed: the kernel computes the digest on demand. If the algorithm is wrong, execs fail closed, and `IntegrityStats.LastHashAlgo` shows the value IMA returned (4 = SHA-256).

## Usage

```bash
# Build the allowlist from an image rootfs. The default scans bin/sbin
# directories; --all hashes every executable (images with /app, /opt, ...).
warmor-integrity-scan --rootfs /path/to/rootfs --all -o integrity-db.json

# Verify a rootfs against a database offline
warmor-integrity-scan --rootfs /path/to/rootfs --verify integrity-db.json

# Report unlisted execs first, scoped to pod cgroups
sudo warmor-daemon --policy policy.wasm --cgroup-filter auto \
  --integrity-db integrity-db.json --integrity-mode audit

# Then refuse them
sudo warmor-daemon --policy policy.wasm --cgroup-filter auto \
  --integrity-db integrity-db.json --integrity-mode enforce
```

`--integrity-db` and `--integrity-mode` must be given together, and an empty database is rejected: enforcing it would refuse every exec.

## Observability

- `warmor_integrity_violations_total{mode="audit|enforce"}`
- Streamed events carry `integrity_violation: true` (and `kernel_enforced: true` when the exec was refused).

## Known limitations

- Tested in VMs, not yet in a live Kubernetes cluster.
- The allowlist is global (the union of all digests loaded), not per container.
- Updating the allowlist requires restarting the daemon with a new database.
