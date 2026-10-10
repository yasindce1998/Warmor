# Policy Diff

`warmor-policy-diff` compares two warmor policy YAML files and shows which rules are unique to each source, which rules changed their decision, and which are confirmed by both. This is useful for understanding the overlap between SBOM-derived and audit-derived policies.

## Installation

```bash
make build-policy-diff
```

## Usage

```bash
# Compare SBOM policy vs audit policy
warmor-policy-diff sbom-policy.yaml audit-policy.yaml

# Summary only (just counts)
warmor-policy-diff --summary sbom.yaml audit.yaml

# Save output to file (flags may appear before, between or after the files;
# use -- to pass a file name that starts with "-")
warmor-policy-diff sbom.yaml audit.yaml -o diff-report.txt --summary
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional args | required | Exactly 2 policy YAML files to compare |
| `-o` | stdout | Output file path |
| `--summary` | `false` | Show only summary counts instead of rule details |
| `--version` | — | Print version and exit |

## Output Format

### Detailed (default)

```
=== Only in sbom-policy.yaml (3 rules) ===
  - [process] allow-dpkg (/usr/bin/dpkg) (allow)
  - [process] allow-apt-get (allow)
  - [file] allow-dpkg-db-access (allow)

=== Only in audit-policy.yaml (2 rules) ===
  - [network] allow-apt-repo-access (allow)
  - [process] allow-cron-job (allow)

=== Changed (1 rules) ===
  - [file] protect-shadow: action deny -> allow

=== In both (5 rules) ===
  - [process] allow-nginx (allow)
  - [process] allow-curl (allow)
  - [file] allow-nginx-conf-read (allow)
  - [file] allow-log-write (allow)
  - [network] allow-outbound-https (allow)
```

### Summary

```
Only in sbom-policy.yaml: 3 rules
Only in audit-policy.yaml: 2 rules
Changed:    1 rules
In both:    5 rules
```

## How It Works

Rules are matched by `(event, conditions)`. A matched pair is reported:

- **In both** when `action`, `mode` and `reason` are also equal (the name may differ; the rule from the first policy is shown);
- **Changed** when any of `action`, `mode` or `reason` differs — e.g. one policy allows what the other denies. The line lists each differing field (`action deny -> allow`, `mode "audit" -> "enforce"`, ...). Use `warmor-policy-merge --strategy deny-wins` to resolve such conflicts.

Duplicate rules (same event and conditions) within one policy are kept and matched one-for-one, so a rule present twice in A and once in B shows one copy "in both" and one "only in A". Condition values JSON cannot represent (YAML `.nan`, `.inf`) are fingerprinted by their Go rendering, so they stay distinct. Each section is sorted by rule name, then event, action, mode, reason and conditions, so the output is deterministic.

## Typical Workflow

```bash
# Generate policies from different sources
warmor-sbom-policy --rootfs ./rootfs sbom.json -o sbom-policy.yaml
warmor-policy-gen audit.ndjson -o audit-policy.yaml

# See what each source uniquely contributes
warmor-policy-diff sbom-policy.yaml audit-policy.yaml

# Rules only in SBOM = declared but never observed (dead weight?)
# Rules only in audit = observed but undeclared (supply chain risk?)
# Rules in both = high confidence allowlist

# Merge with intersection for strict mode
warmor-policy-merge --strategy intersection sbom-policy.yaml audit-policy.yaml -o strict.yaml
```
