# Policy Toolchain

The tools that take a policy from raw inputs to a signed, deployed artifact.
For writing policies by hand, see [policy-authoring.md](policy-authoring.md)
and [rust-policy-examples.md](rust-policy-examples.md).

```
SBOM ──────────► warmor-sbom-policy ─┐
                                      ├─► warmor-policy-merge ─► warmor-compile
Audit log ─────► warmor-policy-gen ──┘            │                (YAML → WASM)
                                                 ▼
                          warmor-policy-diff ◄── merged policy
                                                 │
                                                 ▼
                          warmor-simulate (replay recorded events)
                                                 │
                                                 ▼
                          warmor-policy-bundle (sign + push to OCI registry)
```

All tools are built by `go build -o bin/ ./cmd/...` or the matching
`make build-policy-{merge,diff,bundle}` target. Every tool supports
`--version`.

## SBOM policies — `warmor-sbom-policy`

Generates kernel-level allowlist policies from SPDX 2.3 and CycloneDX 1.4+
JSON SBOMs: only binaries declared in the SBOM are allowed to execute.

```bash
# 1. Generate an SBOM (any SPDX/CycloneDX JSON producer works)
syft nginx:1.25-alpine -o cyclonedx-json > sbom.json

# 2. Extract the container rootfs (needed to map packages → file paths)
docker export $(docker create nginx:1.25-alpine) | tar -C ./rootfs -xf -

# 3. Generate the policy
warmor-sbom-policy --rootfs ./rootfs sbom.json -o policy.yaml
```

`crane export` or `skopeo copy` + `umoci unpack` work too if you don't want
a Docker daemon.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional | required | SBOM JSON file |
| `-o` | stdout | Output YAML file path |
| `--format` | `auto` | SBOM format: `spdx`, `cyclonedx`, or `auto` (detect from JSON) |
| `--level` | `binary` | Enforcement level: `binary`, `library`, or `all` |
| `--rootfs` | `/` | Path to container rootfs for package DB resolution |
| `--name` / `--description` | auto | Policy name / description |
| `--include-interpreters` | `true` | Include known interpreters (python, node, sh) as allowed |

### How it works

Package names alone don't tell the kernel what to allow — file paths do. The
tool reads the container's package database to map each SBOM package to its
installed files:

| Distro | Database Location | Format |
|--------|------------------|--------|
| Alpine (APK) | `/lib/apk/db/installed` | Plain text with P:/F:/R: records |
| Debian/Ubuntu (DEB) | `/var/lib/dpkg/info/<pkg>.list` | One absolute path per line |
| RHEL/Fedora (RPM) | `/var/lib/rpm/Packages.manifest` | Plain-text manifest only (see warning) |

> **RPM warning.** The resolver only reads a plain-text
> `var/lib/rpm/Packages.manifest`, which standard RHEL/Fedora images do not
> ship (they have a binary BerkeleyDB RPM database, which is not parsed).
> On such images the package map comes up empty, so the generated policy has
> **no allow rules at all** — with `default_action: deny` it denies every
> execution. Always inspect the generated YAML (`-o -`) and test in audit
> mode before enforcing. Distroless/Alpine/Debian images are unaffected.

### Enforcement levels

| Level | Included Files | Use Case |
|-------|---------------|----------|
| `binary` (default) | Executables in PATH dirs | Blocks unauthorized process execution; safest starting point |
| `library` | Binaries + shared libraries (`.so`) | Prevents LD_PRELOAD / library injection |
| `all` | Every file from every package | Minimal containers (distroless, scratch) with a small known file set |

Tips: generate SBOMs at build time so they match the deployed image;
`--include-interpreters=false` blocks shell escapes in containers that don't
need scripting runtimes; re-generate when the base image changes.

## Audit-log policies — `warmor-policy-gen`

Auto-generates allowlist policies from audit logs. Run your workload in audit
mode, then generate a least-privilege policy from the observed behavior:

```bash
warmor-daemon --audit --event-sink=file:/tmp/audit.ndjson   # 1. Record
warmor-policy-gen /tmp/audit.ndjson -o policy.yaml          # 2. Generate
# 3. Review and tighten, then compile and enforce
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional | required | Audit log (`.ndjson`), or `-` for stdin |
| `-o` | stdout | Output YAML file path |
| `--name` / `--description` | auto | Policy name / description |
| `--min-count` | `2` | Minimum observation count to include a behavior |
| `--comm-filter` | (all) | Only include events from these processes (comma-separated) |
| `--event-types` | `exec,file,network` | Event types to generate rules for |
| `--collapse-paths` | `true` | Collapse similar paths into glob patterns |
| `--network-group` | `subnet` | Network grouping: `exact`, `subnet`, or `any` |

### How it works

Events are deduplicated into behavior fingerprints — `(comm, filename)` for
exec/file, `(comm, protocol, addr/subnet, port)` for network — and behaviors
seen fewer than `--min-count` times are discarded (filters startup noise).

Similar file paths collapse into globs: `/var/log/app-001.log`,
`app-002.log`, `app-003.log` → `/var/log/app-*.log` (grouped by parent
directory; 3+ paths with a common prefix/suffix and varying middle segment).
`--network-group` controls address aggregation: `exact` (one rule per
`(addr, port)` — tight lockdown), `subnet` (default; collapse /24s via
`starts_with`) or `any` (group by `(protocol, port)` only).

The aggregated behaviors become `allow` rules with `default_action: deny` —
single paths as `eq`, multiple paths as `any_of` variables, collapsed globs
as `glob`, subnet networks as `starts_with`.

Generated policies are a starting point: remove health-check noise, tighten
globs, add explicit deny rules, and put uncertain rules in `mode: audit`.
Record at least one full operational cycle (log rotation, cron jobs) or you
will miss infrequent legitimate behavior.

## Merging policies — `warmor-policy-merge`

Combines multiple policy YAML files into one unified policy — e.g. flatten
SBOM-derived and audit-derived policies before compiling.

```bash
warmor-policy-merge sbom-policy.yaml audit-policy.yaml -o merged.yaml
warmor-policy-merge --dir ./policies -o merged.yaml   # whole directory
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional | — | Input policy YAML files to merge |
| `--dir` | — | Directory of `.yaml`/`.yml` policy files to merge |
| `-o` | stdout | Output file path |
| `--name` / `--description` | auto | Name / description for the merged policy |
| `--strategy` | `union` | Merge strategy (see below) |
| `--annotate` | `true` | Add source provenance to rule reasons |
| `--dedup` | `true` | Deduplicate identical rules and variable entries |
| `--validate` | `false` | Validate merged policy against the compiler schema |

### Merge strategies

| Strategy | Behavior | Best for |
|----------|----------|----------|
| `union` (default) | Keep all rules; allow if *any* input allows | Combining SBOM + audit policies |
| `intersection` | Keep only rules whose fingerprint appears in ≥2 sources | Strict enforcement, multi-source confirmation |
| `deny-wins` | Same fingerprint allow + deny → `deny` | Layering hardening on a permissive baseline |

### How merge works

**Variables:** same-named variables merge (union of values, sorted,
deduplicated). **Rules:** fingerprinted by `(event, conditions)` — name and
action are not part of the fingerprint. **Default action:** strictest wins
(`deny` > `log` > `allow`). **Version:** maximum across inputs. **Name
collisions:** distinct rules with the same name get a numeric suffix.

## Comparing policies — `warmor-policy-diff`

Compares two policy YAML files: which rules are unique to each source, which
changed their decision, and which are confirmed by both.

```bash
warmor-policy-diff sbom-policy.yaml audit-policy.yaml
warmor-policy-diff --summary sbom.yaml audit.yaml   # counts only
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional | required | Exactly 2 policy YAML files |
| `-o` | stdout | Output file path |
| `--summary` | `false` | Show only summary counts instead of rule details |

Rules are matched by `(event, conditions)`. A matched pair is **in both**
when `action`, `mode` and `reason` also equal (names may differ), or
**changed** when any of them differs (`action deny -> allow`) — resolve
conflicts with `warmor-policy-merge --strategy deny-wins`. Output sections
are sorted deterministically.

Reading the diff: rules only in the SBOM are declared but never observed
(dead weight?); rules only in the audit log are observed but undeclared
(supply-chain risk?); rules in both are a high-confidence allowlist.

## Simulating policies — `warmor-simulate`

> **Status: Shipped** (`warmor-simulate`). The **daemon has no event-store
> sink** on `main`, and the policy server does not call the simulator.
> Record events with the file sink, using a file name that matches
> `events-*.ndjson`. See [Feature Status](STATUS.md).

Replays recorded security events against a candidate policy (YAML or
compiled WASM) and reports the impact before you deploy it — new denials and
new allows are compared against the original recorded decisions and
deduplicated, using the same WASM policy engine used at runtime.

```bash
sudo warmor-daemon --policy current.wasm --audit \
  --event-sink file:/var/lib/warmor/events/events-current.ndjson
warmor-simulate --policy strict.yaml --data /var/lib/warmor/events --since 24h
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | required | Path to candidate policy file (.yaml or .wasm) |
| `--data` | required | Path to the event directory (every `events-*.ndjson` is read) |
| `--since` | `7d` | Only replay events from this duration ago |
| `-o` | stdout | Output file path |
| `--format` | `text` | Output format: `text` or `json` |

Text output shows the decision breakdown (ALLOW/DENY/LOG percentages) plus
unique new-denial patterns (`exec python3 /usr/bin/python3 42`); JSON output
contains the same data as a structured object.

## Distributing policies — `warmor-policy-bundle`

Packages compiled `.wasm` policies as OCI artifacts and pushes/pulls them
to/from container registries — versioned policy distribution using the same
infrastructure as container images. Bundles are signed with an ed25519 key
on push and verified on pull. Pull fails closed: without `--verify-key` (or
the explicit `--insecure-skip-verify` opt-out) nothing is downloaded.

### Key management

```bash
# Generate a signing key pair
warmor-policy-bundle --keygen --sign-key signing.key --verify-key signing.pub
```

`signing.key` is a PKCS#8 PEM private key (written with mode 0600); keep it
in your CI secret store. `signing.pub` is a PKIX PEM public key; distribute
it to every node that pulls policies. Existing files are never overwritten.
Keys generated by `warmorctl` (Certs → "Generate policy signing key pair")
use the same format.

### Push and pull

```bash
# Push (prints the manifest digest)
warmor-policy-bundle --push \
  --ref ghcr.io/myorg/warmor-policies/nginx:v1.0.0 \
  --wasm policy.wasm --sign-key signing.key \
  --name nginx-hardening --policy-version 1.0.0

# Pull (pin to digest for deployments — see rollback note below)
warmor-policy-bundle --pull \
  --ref ghcr.io/myorg/warmor-policies/nginx@sha256:<digest> \
  --wasm ./downloaded-policy.wasm --verify-key signing.pub
```

The pull output file is written atomically and only after every check
passes; on failure an existing file at `--wasm` is left untouched.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--push` / `--pull` | — | Push / pull a .wasm policy |
| `--ref` | required | OCI reference (e.g., `ghcr.io/org/policy:tag`) |
| `--wasm` | required | Path to .wasm file (input for push, output for pull) |
| `--name` | `warmor-policy` | Policy name stored in artifact metadata |
| `--policy-version` | `1.0.0` | Policy version stored in artifact metadata |
| `--description` | — | Policy description stored in artifact metadata |
| `--keygen` | — | Generate a key pair at `--sign-key` / `--verify-key` and exit |
| `--sign` | — | Write the detached signature `<wasm>.sig` for `--wasm` and exit |
| `--verify` | — | Check `--wasm` against `<wasm>.sig` with `--verify-key` and exit |
| `--sign-key` | required for push | ed25519 private key PEM used to sign on push |
| `--verify-key` | required for pull | ed25519 public key PEM used to verify on pull |
| `--allow-unsigned` | `false` | Push without a signature (INSECURE) |
| `--insecure-skip-verify` | `false` | Pull without verifying the signature (INSECURE) |
| `--max-wasm-size` | 64 MiB | Largest wasm layer accepted on pull |

### OCI artifact structure and signatures

The bundle uses the standard OCI image manifest format: a config blob
(`application/vnd.warmor.policy.config.v1+json` — name, version,
description), exactly one wasm layer
(`application/vnd.warmor.policy.wasm.v1`), and an
`org.warmor.policy.signature` manifest annotation holding a base64 ed25519
signature.

Because a manifest cannot contain a signature over its own digest, the
signature covers the content-addressed descriptors the manifest references
(config + layers). Since every blob is fetched and checked against its
digest, the signature transitively authenticates the wasm and config
contents. Other manifest annotations are informational and not signed.

A signature binds content, not a tag: a registry could serve an older
bundle that was signed with the same key under a newer tag. Pin deployments
by digest (`ref@sha256:...`) to rule out rollback, and use distinct keys
for policies that must not be interchangeable.

Pull checks before downloading any blob: OCI image manifest media type and
≤1 MiB size (and digest match when pinned); `artifactType` empty or the
config media type; exactly one wasm layer within `--max-wasm-size`; valid
signature from `--verify-key` (unless `--insecure-skip-verify`).

### Detached signatures (daemon and policy server)

`warmor-daemon --verify-key` and `warmor-server --verify-key` do not read
OCI bundles; they check a **detached signature** stored next to the module
as `<policy>.sig`. It uses the same key pair, but signs the exact `.wasm`
bytes directly:

```bash
warmor-policy-bundle --sign --wasm policies/policy.wasm --sign-key signing.key
warmor-policy-bundle --verify --wasm policies/policy.wasm --verify-key signing.pub
```

Ed25519 signatures are deterministic, so OpenSSL 3 produces a byte-identical
signature from the same PKCS#8 key:

```bash
openssl pkeyutl -sign -inkey signing.key -rawin -in policies/policy.wasm | base64 -w0 > policies/policy.wasm.sig
```

**Daemon behavior with `--verify-key`:** startup verifies `--policy` against
its `.sig` and loads those exact bytes from memory (before any BPF program
loads; failure exits the daemon). Reload (SIGHUP on Linux/macOS, the file
watcher on Windows) runs the same check and keeps the current policy on
failure. Policy-server downloads are verified in memory before anything is
written to disk; a rejected download keeps the old policy and increments
`warmor_policy_signature_failures_total`. YAML policies are refused under
`--verify-key` — compile, sign the `.wasm`, and point `--policy` at it.

`warmor-daemon --validate-policy <path>` loads a policy in a throwaway WASM
runtime (checking its signature when `--verify-key` is given), prints the
result and exits 0 or 1. No root, no BPF. The Helm chart's
`validate-policy` initContainer runs it. For YAML without `--verify-key` it
checks the schema and loads a precompiled sibling `.wasm` if one exists
(it does not compile the YAML).

**Policy server:** upload policies that are already signed, so the private
key never has to be on the server. Put `<wasm>.sig` next to the module in
`--policy-dir`, or pass the base64 signature as `"signature"` in the
create/update request body. With `warmor-server --verify-key` the server
rejects unsigned or failing uploads with HTTP 422; the signature is served
back in the `X-Warmor-Policy-Signature` header of `/api/v1/policy/wasm`.

Since `--pull` writes only the `.wasm` and the bundle signature cannot be
turned into a detached one, also run `--sign` in CI and ship the `.sig`
next to the module (e.g. in the same ConfigMap or Secret) when nodes run
`warmor-daemon --verify-key`.

### Authentication

None on `main`: the tool connects to the registry **anonymously**. No
Docker credential chain (`~/.docker/config.json`), environment variable or
credential helper is read, so pushes and pulls against registries that
require authentication fail. Use a registry that allows anonymous pull (or
anonymous push, e.g. a local ZOT instance) until credential support is
wired in.

## Typical end-to-end workflow

```bash
# 1. Generate policies from different sources
warmor-sbom-policy --rootfs ./rootfs sbom.json -o sbom-policy.yaml
warmor-policy-gen audit.ndjson -o audit-policy.yaml

# 2. Compare, then merge
warmor-policy-diff sbom-policy.yaml audit-policy.yaml
warmor-policy-merge --validate sbom-policy.yaml audit-policy.yaml -o merged.yaml

# 3. Test against recorded events
warmor-simulate --policy merged.yaml --data /var/lib/warmor/events --since 7d

# 4. Compile, sign and push
warmor-compile merged.yaml -o policy.wasm
warmor-policy-bundle --push \
  --ref ghcr.io/myorg/warmor-policies/myapp:v1.0.0 \
  --wasm policy.wasm --sign-key signing.key --name myapp-policy

# 5. Pull and verify on deployment nodes, then enforce
warmor-policy-bundle --pull \
  --ref ghcr.io/myorg/warmor-policies/myapp@sha256:<digest> \
  --wasm /etc/warmor/policy.wasm --verify-key /etc/warmor/signing.pub
warmor-policy-bundle --sign --wasm /etc/warmor/policy.wasm --sign-key signing.key  # in CI, actually
sudo warmor-daemon --policy /etc/warmor/policy.wasm --verify-key /etc/warmor/signing.pub
```
