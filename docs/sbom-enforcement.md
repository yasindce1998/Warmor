# SBOM Enforcement

`warmor-sbom-policy` generates kernel-level allowlist policies from SPDX and CycloneDX SBOMs. Only binaries declared in the SBOM are allowed to execute — everything else is denied at the kernel level.

## Workflow

```
1. Generate:  syft <image> -o cyclonedx-json > sbom.json
2. Extract:   docker export $(docker create <image>) | tar -C ./rootfs -xf -
3. Policy:    warmor-sbom-policy --rootfs ./rootfs sbom.json -o policy.yaml
4. Compile:   warmor-compile policy.yaml -o policy.wasm
5. Enforce:   warmor-daemon --policy policy.wasm
```

## Installation

```bash
go install github.com/yasindce1998/warmor/cmd/warmor-sbom-policy@latest
```

Or build from source:

```bash
cd cmd/warmor-sbom-policy && go build -o warmor-sbom-policy .
```

## Usage

```bash
warmor-sbom-policy [flags] <sbom.json>
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-o` | stdout | Output YAML file path |
| `--format` | `auto` | SBOM format: `spdx`, `cyclonedx`, or `auto` (detect from JSON) |
| `--level` | `binary` | Enforcement level: `binary`, `library`, or `all` |
| `--rootfs` | `/` | Path to container rootfs for package DB resolution |
| `--name` | auto from SBOM | Policy name |
| `--description` | auto-generated | Policy description |
| `--include-interpreters` | `true` | Include known interpreters (python, node, sh) as allowed |
| `--version` | — | Print version and exit |

### Examples

```bash
# Generate from a CycloneDX SBOM (auto-detected)
warmor-sbom-policy --rootfs ./rootfs sbom.json -o policy.yaml

# Explicit SPDX format, library-level enforcement
warmor-sbom-policy --format spdx --level library --rootfs ./rootfs sbom.json

# All files (strictest), no interpreters
warmor-sbom-policy --level all --include-interpreters=false --rootfs ./rootfs sbom.json

# Pipe to stdout for inspection
warmor-sbom-policy --rootfs ./rootfs sbom.json
```

## How It Works

### Step 1: Parse SBOM

The tool reads SPDX 2.3 or CycloneDX 1.4+ JSON files. Format is auto-detected by looking for `spdxVersion` or `bomFormat` keys. Both formats are normalized into a unified package list with name, version, type, and hashes.

### Step 2: Resolve Packages to File Paths

Package names alone don't tell the kernel what to allow — file paths do. The tool reads the container's package database to map each SBOM package to its installed files:

| Distro | Database Location | Format |
|--------|------------------|--------|
| Alpine (APK) | `/lib/apk/db/installed` | Plain text with P:/F:/R: records |
| Debian/Ubuntu (DEB) | `/var/lib/dpkg/info/<pkg>.list` | One absolute path per line |
| RHEL/Fedora (RPM) | `/var/lib/rpm/Packages.manifest` | Plain-text manifest only (see warning) |

This requires access to the container's filesystem via `--rootfs`.

> **RPM warning.** The resolver only reads a plain-text
> `var/lib/rpm/Packages.manifest`, which standard RHEL/Fedora images do not
> ship (they have a binary BerkeleyDB RPM database, which is not parsed).
> On such images the package map comes up empty, so the generated policy has
> **no allow rules at all** — with `default_action: deny` it denies every
> execution. Always inspect the generated YAML (`-o -`) and test in audit
> mode before enforcing. Distroless/Alpine/Debian images are unaffected.

### Step 3: Filter by Enforcement Level

| Level | Included Files | Use Case |
|-------|---------------|----------|
| `binary` | Executables in PATH dirs (`/usr/bin`, `/sbin`, etc.) | Default — blocks unauthorized process execution |
| `library` | Binaries + shared libraries (`.so` files) | Prevents library injection attacks |
| `all` | Every file from every package | Strictest — blocks any undeclared file access |

### Step 4: Generate Policy

The resolved file paths become a warmor allowlist policy:

- Binaries → `process` event rules with `any_of` variable
- Libraries → `file` event rules with `any_of` variable
- Default action → `deny`

## Example Output

Given a CycloneDX SBOM from an Alpine nginx image:

```yaml
name: nginx-1-25-alpine-sbom-policy
version: 1
description: "SBOM-derived allowlist (47 packages, 23 binaries) from nginx:1.25-alpine"

variables:
  sbom-binaries:
    - /bin/bash
    - /bin/sh
    - /usr/bin/envsubst
    - /usr/bin/getconf
    - /usr/bin/getent
    - /usr/bin/njs
    - /usr/sbin/nginx

rules:
  - name: allow-sbom-binaries
    event: process
    conditions:
      all:
        - path:
            any_of: $sbom-binaries
    action: allow
    reason: "Binary declared in SBOM (CycloneDX nginx:1.25-alpine)"

default_action: deny
```

## Extracting Container Rootfs

The `--rootfs` flag points to an extracted container filesystem. Several methods to obtain it:

```bash
# Method 1: docker export
docker export $(docker create nginx:1.25-alpine) | tar -C ./rootfs -xf -

# Method 2: crane (no Docker daemon needed)
crane export nginx:1.25-alpine - | tar -C ./rootfs -xf -

# Method 3: skopeo + umoci
skopeo copy docker://nginx:1.25-alpine oci:nginx-oci
umoci unpack --image nginx-oci:latest bundle
# rootfs is at ./bundle/rootfs/
```

## Supported SBOM Generators

Any tool producing SPDX 2.3 or CycloneDX 1.4+ JSON works:

| Tool | Command |
|------|---------|
| [Syft](https://github.com/anchore/syft) | `syft nginx:alpine -o cyclonedx-json` |
| [Trivy](https://github.com/aquasecurity/trivy) | `trivy image --format cyclonedx nginx:alpine` |
| [Docker Scout](https://docs.docker.com/scout/) | `docker scout sbom nginx:alpine --format spdx` |

## Enforcement Levels

### `binary` (default)

Only restricts process execution. An attacker who gains code execution in an existing process can still read/write files, but cannot spawn new processes outside the SBOM.

Best for: general-purpose containers where file access patterns are too broad to enumerate.

### `library`

Restricts process execution AND shared library loading. Prevents LD_PRELOAD attacks and unauthorized library injection.

Best for: containers with a well-defined set of libraries (static-linked binaries don't need this).

### `all`

Restricts access to every file. Only files installed by SBOM-declared packages are accessible.

Best for: minimal containers (distroless, scratch-based) where the full file set is known and small.

## Tips

- **Generate SBOMs at build time** — embed the SBOM in your CI pipeline so it matches the exact image being deployed.
- **Use `--include-interpreters=false`** for containers that don't need shells or scripting runtimes — this blocks shell escape attacks.
- **Start with `binary` level** — it's the safest default. Move to `library` or `all` only after testing in audit mode.
- **Combine with audit-mode** — deploy the generated policy in audit mode first to catch any legitimate binaries missing from the SBOM.
- **Re-generate on image update** — when the base image changes, re-run the SBOM generator and `warmor-sbom-policy` to update the allowlist.
