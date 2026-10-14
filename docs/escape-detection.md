# Container Escape Detection

> **Status: Shipped (detection).** `warmor-daemon --escape-detect=alert|deny` checks every event against the patterns below, scoped to container cgroups. Detection runs in userspace after the kernel has allowed the operation. In `deny` mode the offending process is terminated, which is enforcement after the fact, not prevention. To block a technique synchronously, deny it in your policy so it reaches the kernel fast path. See [Feature Status](STATUS.md).

## Usage

```bash
# Log, count and label matches; change no decisions
sudo warmor-daemon --policy policy.wasm --escape-detect alert --event-sink stdout

# Also terminate the matching process
sudo warmor-daemon --policy policy.wasm --escape-detect deny
```

Matches are:
- logged as `[WARN] escape attempt: ...`;
- counted in `warmor_escape_alerts_total{technique}`;
- labelled on streamed events with `escape_technique` and `escape_name`.

An attempt the kernel already refused (a policy-map deny) is alerted, but not killed.

## Scope: containers only

Escape techniques are only escapes from inside a container: a host administrator running `nsenter` is not one. Each event's cgroup id is resolved to a container by walking the cgroup v2 hierarchy, recognizing containerd (`cri-containerd-<id>`), CRI-O (`crio-<id>`), Docker (`docker-<id>`), podman (`libpod-<id>`) and bare 64-hex ids. The runtime monitor scopes (`crio-conmon-*`, `libpod-conmon-*`) are not containers. Events from host cgroups are ignored.

## Detected patterns

| Technique | ID | Severity | Matches |
|-----------|----|----------|---------|
| nsenter from container | T1611.001 | Critical | exec of a binary named `nsenter` |
| Host filesystem mount | T1611.002 | Critical | mount of a block device (`/dev/sd*`, `/dev/vd*`, `/dev/nvme*`, `/dev/mapper/*`, ...) or a cgroup v1 hierarchy (the `release_agent` escape), except by the container runtime's own init (`runc`, `crun`, `youki`, `conmon`, `containerd-shim`) |
| Cross-cgroup ptrace | T1055.008 | Critical | ptrace of a process in a different cgroup |
| `/proc` namespace access | T1611.003 | High | open of `/proc/<pid>/ns/*`, `/proc/self/ns/*` or `/proc/thread-self/ns/*` |
| unshare + setns | T1611.004 | Critical | exec of `unshare`, then a namespace handle open within 5s |
| Container runtime socket | T1610 | High | connect to the Docker, containerd, CRI-O or podman API socket |
| Sensitive binary execution | T1059.004 | High | exec of `runc`, `ctr`, `crictl`, `kubectl`, `docker`, `nerdctl`, `chroot`, `capsh`, `setcap` or `debugfs` |

Exec patterns match the binary being executed, not `comm`: at exec time `comm` is still the calling process's name.

## Where the data comes from

- **mount:** `lsm/sb_mount` reports the filesystem type and the mount source.
- **ptrace:** `lsm/ptrace_access_check` reports the target's comm and cgroup id.
- **Runtime sockets:** with detection on, the daemon loads the runtime socket paths into the kernel map `unix_watch`, and `lsm/socket_connect` reports AF_UNIX connects to them. Other unix connects are not reported (there are far too many).
- **`/proc/*/ns/*` opens:** the `openat` tracepoint, which sees the path as passed. A relative path (`ns/mnt` after `chdir /proc/1`) is not matched.

## Known limitations

- Detection is after the fact: the operation has already been allowed by the kernel.
- Opens via relative paths, and runtime sockets at non-standard paths, are not matched.
- Patterns are built in; there is no configuration for custom patterns yet.
