# Container Escape Detection

> **Status: Experimental, library only.** This describes the Go package `internal/escape`, which has unit tests but is **not wired into `warmor-daemon` or `warmor-server` on `main`**. No binary, flag or config value reaches it. Nothing on this page runs in a deployed agent today, and no escape is blocked. See [Feature Status](STATUS.md).

The escape detector correlates security events against known container escape patterns. It is designed to raise alerts, and optionally return a deny decision, when a breakout attempt is identified.

## Detected Escape Patterns

| Technique | MITRE ID | Severity | Description |
|-----------|----------|----------|-------------|
| nsenter from container | T1611.001 | Critical | Process executes `nsenter` to enter the host namespace |
| Host filesystem mount | T1611.002 | Critical | Container mounts host paths (`/`, `/etc`, `/var`, `/proc/1/root`) |
| Cross-cgroup ptrace | T1055.008 | Critical | Process attempts to ptrace a target in a different cgroup |
| /proc namespace access | T1611.003 | High | Access to `/proc/*/ns/*` indicating namespace manipulation |
| unshare + setns sequence | T1611.004 | Critical | `unshare` exec followed by namespace file access within 5 s |
| Docker socket access | T1610 | High | Read/write to `docker.sock` or `containerd.sock` |
| Sensitive binary execution | T1059.004 | High | Execution of escape tools (`runc`, `ctr`, `crictl`, `mount`, `chroot`, `capsh`, etc.) |

## How Detection Works

### Single-Step Patterns

Most patterns are single-step: one event matches one condition and immediately triggers an alert. Examples include `nsenter` execution or Docker socket access.

### Multi-Step Correlation (Sliding Window)

Some escape techniques require a sequence of operations. The detector maintains a **per-cgroup sliding window** (30-second buffer) of recent events and correlates them against multi-step patterns:

1. Each incoming event is checked against the **last step** of every multi-step pattern.
2. If the last step matches, the detector walks backward through the cgroup's event window looking for prior steps.
3. All prior steps must have occurred within the pattern's configured time window (e.g., 5 seconds for unshare + setns).
4. If every step is satisfied, an alert fires.

Events older than 30 seconds are automatically trimmed from the window.

### Event Fields Used for Matching

The detector inspects: `EventType`, `Comm`, `Filename`, `CgroupID`, `PID`, `PPID`, `UID`, `MountType`, `PtraceComm`, `RemoteAddr`, and `LocalPort`.

## Planned Integration with Enforcer (not wired on main)

The detector exposes two entry points. **Neither is called by the enforcer on `main`**, and there is no `--escape-detect` flag yet.

**Inline check** (`CheckEvent`) — intended to be called by the enforcer on every security event. With `DenyOnDetect` enabled, it returns an `ActionDeny` result. Once wired, that deny would be enforced like any other userspace deny (`SIGKILL` after the event). It would not block in the kernel.

**Event enrichment** (`Enrich`) — tags events with `escape_technique` and `escape_name` labels for downstream consumers (logging, SIEM export, alerting dashboards).

### Configuration

```go
detector := escape.NewDetector(escape.DetectorConfig{
    Patterns:     escape.DefaultPatterns(), // or custom subset
    DenyOnDetect: true,                     // block syscall on match
    AlertCallback: func(a *escape.Alert) {
        log.Printf("escape: %s (pid=%d cgroup=%d)", a.Name, a.PID, a.CgroupID)
    },
})
```

Set `DenyOnDetect: false` to run in audit/alert-only mode without blocking.

## MITRE ATT&CK Mapping

| Warmor Technique | ATT&CK ID | ATT&CK Technique |
|------------------|-----------|-------------------|
| nsenter from container | T1611.001 | Escape to Host: nsenter |
| Host filesystem mount | T1611.002 | Escape to Host: Mount host FS |
| Cross-cgroup ptrace | T1055.008 | Process Injection: Ptrace |
| /proc namespace access | T1611.003 | Escape to Host: Namespace manipulation |
| unshare + setns sequence | T1611.004 | Escape to Host: Namespace attach |
| Docker socket access | T1610 | Deploy Container (lateral movement) |
| Sensitive binary execution | T1059.004 | Command and Scripting Interpreter |

## Tips

- **Start in audit mode** (once wired) — set `DenyOnDetect: false` first to observe alerts without impacting workloads.
- **Combine with SBOM enforcement** — escape detection catches active breakout attempts while SBOM policies prevent unauthorized binaries from running in the first place.
- **Monitor alert callbacks** — feed alerts into your SIEM to correlate escape attempts with other cluster signals.
- **Custom patterns** — pass a filtered `Patterns` slice to scope detection to your threat model.
