# Installing the experimental supervised host

The backend is **off by default**, Linux-only, and not a native-code sandbox.
See `supervised-policy-host.md` for limits and `policyhost-declarations.md` for
the separate declaration trust boundary. Packaging is not VM outcome evidence.

Linux binary archives include `warmor-policy-host`, `POLICY_HOST_SHA256`, and the
usual `SHA256SUMS`. Windows and macOS archives do not include this Linux helper.
The daemon image builds both executables from the same source/build stage and
installs the helper at `/usr/local/libexec/warmor-policy-host`, owned by root and
mode 0755. `/usr/share/warmor/POLICY_HOST_SHA256SUMS` records its exact build hash
(the recorded `/warmor-policy-host` name is the **build-stage** path). Read this
public metadata from the exact digest-pinned image outside the distroless
container, then supply that hash explicitly at runtime. No signing key, default
verification key, secret environment variable, or automatic pin discovery ships.

For example, after verifying archive/image provenance and installing both from
the same revision:

```sh
warmor-daemon --policy /etc/warmor/signed-policy.wasm \
  --verify-key /etc/warmor/test-or-admin-public.pem \
  --experimental-supervised-policy-host \
  --policy-host /usr/local/libexec/warmor-policy-host \
  --policy-host-sha256 <64-lowercase-hex-from-verified-artifact>
```

Keep the existing audit/scope/LSM configuration explicit. `--policy-host-load-timeout`
defaults to 5s within the 10s total initialization budget; `--eval-timeout` bounds
each request. No failure falls back to the in-process evaluator. Signatures
authenticate module bytes, **not** exhaustive/deterministic declarations. Leave
`--policy-declaration-digests` empty unless those exact modules have been reviewed;
only then attest their SHA-256 values. This is required for supervised static
default-deny and decision caches, and is not implied by the executable pin.

## Physical path and upgrade assumptions

Every path component must be physical (no symlinks), owned by root or the daemon
effective UID, and not group/other writable (root-owned sticky directories are
the limited exception). `/bin` on merged-/usr hosts and projected Kubernetes
ConfigMap helper paths are unsuitable. The executable must be regular,
executable, non-setuid/setgid and non-group/other-writable. `/proc`, `/dev/null`,
Linux 5.11+ and the required `close_range` flags must be available. Container
seccomp/LSM profiles must allow bootstrap; failure is fatal, never a fallback.

An administrator with write access remains trusted. **Never overwrite a running
helper inode in place**: install a new root-owned versioned directory/file and
atomically rename it, then update the explicit pin and restart the daemon as one
coordinated deployment. A running daemon retains its old pin; replacing its path
with different bytes makes future activations fail closed while LKG remains
owned. Descriptor execution closes path-swap races, not malicious writes to an
already-open inode. Roll back daemon, helper and pin together.

The Helm chart intentionally has no host opt-in yet: it stays audit-safe and
does not wire signed policy/key mounts. Do not smuggle the helper through a new
hostPath or enable it by default. Chart integration belongs with that signed
configuration work, not this packaging gate.

## Evidence and remaining infrastructure

`tests/integration/run-outcomes.sh --policy-host [--atomic-generations]` reuses
the disposable-VM isolation guard, exact prepared binaries and outcome oracle.
`--build-only` never starts a daemon or VM. Ephemeral fixture private keys exist
only in preparation memory; retained keys are public. Dedicated CI must supply
actual BPF-LSM VM results for both map modes. Neither compile-only tests nor
mock launchers prove prevention, termination or shutdown resource ordering.
The deterministic real-host/fake-kernel lease tests separately check old hosts
and maps survive Stop/leases until Close; VM SIGTERM probes check bounded clean
exit and child reaping, not an instrumented proof of every map-teardown instant.
Native arm64/container bootstrap, deployment updates, blocked-seccomp profiles,
and Windows/macOS equivalents remain platform/infrastructure validation work.

This gate verifies detached **artifact signatures**, not signed deployment
intent. PR53's `--signed-assignments` + Host/atomic refusal remains in force;
neither the fixture nor declaration pins enable those unsupported combinations.
Live event recordings stay under physical guest-owned
`/tmp/warmor-outcome-fixtures/recordings` (0700), never on the shared checkout;
they are exported as private evidence only after the daemon exits.
