# Toolchain subprocess bounds

`BuildOptions.Context` cancels Rust target discovery and Cargo builds. Target
discovery also has a 10-second timeout, including through `CargoAvailable`.
With a nil context, compilation retains the historical no-deadline CLI behavior.
Each command captures at most **1 MiB total stdout plus stderr**, shared across
both streams. Exceeding that budget fails the build even if the tool exits zero.
Verbose mode prints only that bounded capture after completion; it no longer
streams arbitrary output into a potentially blocking consumer during execution.

On **Linux and Darwin**, each command starts a fresh process group. Cancellation,
output overflow and ordinary parent exit trigger SIGKILL of that owned group
**before** reaping the parent. Linux and Darwin observe exit with native
`waitid(WNOWAIT)` and recheck wait ownership immediately before signaling.
Keeping the leader unreaped reserves the group ID until signaling finishes. We
never discover and kill an arbitrary group, signal group zero, or fall back to
positive-PID tree enumeration. A failed ownership probe (including `ECHILD`)
reports failure without signaling a potentially reused group ID. Darwin checks `P_NOCLDWAIT`
before `Start` and again before cleanup, rejecting SIGCHLD `SIG_IGN` and
`SA_NOCLDWAIT` without changing the application's signal disposition. Unlike a
kqueue `ESRCH` notification, `waitid` checks that the PID is still our child.
On Darwin, SIGKILL can return `EPERM` for a group consisting only of zombies.
We accept that result only after an owned-group kernel query finds no live
member, includes our unreaped child leader, and a second wait probe succeeds.
Permission errors for live members and inspection failures remain errors.

**Exclusive-reaper precondition:** applications must not reap compiler children
behind `os/exec` or change auto-reap signal settings while a tool runs. The
Darwin auto-reap check enforces the detectable pre-start configuration; it
cannot lock out arbitrary application threads, native signal handlers, or
external waiters in the same process. A concurrent reaper between the final
ownership probe and signaling is unsupported, not made safe by `WNOWAIT`.
No global signal disposition is installed or changed by the compiler.

Go's pipe-copy goroutines write only to bounded, nonblocking internal capture
writers and are joined before return. A one-second pipe wait closes inherited
output pipes if a descendant has left the group. Failed commands cannot publish
their generated artifact, and failed build temporary crates are removed. Context
cancellation is checked again before writing the destination artifact. Contexts
do not interrupt ordinary filesystem operations or synchronous verbose printing
after the subprocess is cleaned up.

**Windows and other operating systems retain parent-only cancellation.** Output
and discovery bounds still apply, but there is no claim of child-tree cleanup.
A correct Windows implementation needs a Job Object with kill-on-close ownership
established before any child can spawn; assigning an already running process
would leave a race and is deliberately not presented as containment here.

These are **lifetime and captured-output bounds, not a sandbox**. They do not
limit CPU, RSS, disk consumption, network access, privileges, or escaped sessions.
A deliberately hostile executable can leave its group with `setsid`/`setpgid`;
it requires an external sandbox for stronger isolation. Parent application death
is likewise not a portable process-group cleanup guarantee. No host process
resource limits, global reapers, privileged cgroups, or unrelated processes are
changed by this implementation or its tests.
