# Compiler artifact publication

`compiler.Build` previously copied Cargo's raw WASM to `OutputPath`, then read
that destination, appended `warmor.build.v1`, and wrote it a second time. A bad
artifact, metadata error, cancellation, or second-write failure could destroy a
previous artifact even though the build returned an error.

## Publication contract

- Cargo's output remains under the private `warmor-compile-*` crate directory
  (`MkdirTemp`, mode 0700 on Unix). Generated sources and Cargo files are not
  staged beside the destination. Failed builds remove the crate; successful
  callers retain the existing `Cleanup(result)` responsibility.
- Cargo normally hard-links its release artifact into `deps`. Use `cargo rustc`
  with `--emit=link=<sanitized WASM basename>` and the private crate as its working
  directory to get a singly-linked output directly from rustc, rather than
  accepting or copying a multiply-linked input. Never put the full temp path in
  `--emit`: rustc treats commas as emission separators even in one argv entry.
  The full crate path is retained for reading. Release profile and generated code
  are unchanged.
- Read only singly-linked regular, non-symlink Cargo output. Check its size
  before reading, verify the opened handle's link count and pathname identity,
  and also limit the read to 64 MiB plus one byte to detect growth. Recheck the
  handle's link count after reading. Unix uses handle-stat `Nlink`; Windows uses
  `GetFileInformationByHandle.NumberOfLinks`. If link count cannot be established,
  fail closed. Reject a final metadata-bearing artifact larger than 64 MiB.
- Run `policybuild.Append` before any destination access. This checks the WASM
  header/section framing and rejects malformed, existing, or duplicate build
  declarations. It is not general WASM semantic or ABI validation; runtime
  loading still provides those checks. Compiler identity remains
  `warmor-yaml/7`; generated code, ABI, and cache keys are unchanged.
- Stage complete final bytes in a unique file in the destination's parent,
  set permissions, sync the file, close it, check cancellation, then replace.
  Unix uses rename followed by parent-directory sync. Windows follows the
  existing agentstore/policyserver pattern with `MoveFileEx` using
  `REPLACE_EXISTING | WRITE_THROUGH`, not a remove-then-rename fallback.
- An ordinary pre-commit failure preserves the destination and removes the
  staging file. Cancellation is checked immediately before replacement, not
  after a successful commit. Process death can leave a staging file; cleanup
  on crashes is not promised.
- `errors.Is(err, compiler.ErrArtifactPublicationIndeterminate)` means the
  destination may already contain the complete new artifact and durability
  could not be confirmed. Inspect it before use/retry; do not assume the old
  artifact survived. This includes post-rename directory sync/close errors and,
  conservatively, Windows write-through move errors. `Build` returns no result
  on any error and cleans its private crate even for this outcome.

## Compatibility and scope

`OutputPath` still defaults to `policy.wasm`, and a successful result still has
an absolute `WasmPath`. New files retain `CreateTemp`'s private 0600 permissions,
further restricted by the caller's umask on Unix. This is intentionally more
restrictive than the previous 0644 creation request: no chmod widens new-file
permissions past the caller's umask, and no process-wide umask is read or changed.
Existing singly-linked regular-file permission bits are retained on Unix.
Existing read-only outputs are rejected (including when
rename permission on the parent would otherwise bypass them). Replacement
changes the inode and does not promise to preserve ownership, ACLs, extended
attributes. Hard-linked destinations are rejected, not detached from their
aliases. It is intended for compiler-owned artifacts
in a caller-controlled, stable directory with one coordinated publisher, not
as an attacker-writable-directory security boundary.

Intentional tightening: symlink, hard-linked, and special-file outputs, including
FIFOs, are rejected rather than followed/written. Use a singly-linked regular
destination path instead. Cargo output is subject to the same restriction.
Unsupported platforms fail closed rather than skipping handle safety checks.
Parent symlinks are not prohibited. The output leaf is opened without following symlinks and
without truncation when checking existing permissions; replacement itself does
not follow a destination symlink. This is not protection against a malicious
same-user toolchain or concurrent replacement of parent directories.

`Build` publishes **only the WASM file**, never its `.sig` sidecar. An existing
signature is untouched and may no longer match after compilation. Sign the
final bytes after a successful build and use verified-byte loading; this does
not make WASM/signature publication pair-atomic. CLI, controller, and YAML cache
callers continue to propagate build errors without claiming the old file was
preserved. Their separate cache publication policies are unchanged.

This is separate from PR #52's compiler process-bounds work, whose review
explicitly left the two-write flow out of scope. No process lifetime/output
changes, CPU/RSS limits, sandboxing, host enforcement, or live-infrastructure
claims are included here.

## Combining with PR #52 later

This branch starts at main `c4887c8`, not the process-bounds branch. The intentional
overlap is `internal/compiler/build.go`:

1. Keep PR #52's tool runner, deadline, cancellation, and diagnostic bounds in
   `checkCargoContext` and `cargoBuild`.
   Retain this branch's `cargo rustc ... -- --emit=link=<sanitized basename>`
   arguments with `cmd.Dir = crateDir`, so Cargo does not hard-link the candidate
   into its artifact cache and comma-containing temp parents remain valid.
2. Keep `cargoBuild` returning **only** its private `builtPath`; discard its old
   destination resolution/read/write tail, including any pre-write context
   check there.
3. Keep main's post-Cargo context check, this branch's bounded read and metadata
   append in `Build`, and its one call to `artifactPublisher.publish`.
4. Preserve the pre-commit context check in the publisher. Do not reintroduce
   a post-commit cancellation failure or a second write to the destination.
5. Run the process-bounds and publication tests together, plus the real Cargo
   signed-assignment/ABI test. No metadata should be removed while resolving
   the overlapping old-branch diff.

Targeted validation uses Go 1.26.11 with `-p 2`: compiler/policybuild unit and race
tests, plus the real Cargo
`TestCompiledAssignmentRetainsBuildContextSafeIdentifierAndMetadata` test in
`internal/wasm`. Windows and Darwin build checks are compilation evidence only,
not native filesystem/durability test results. The real-Cargo permissions test
runs in a fresh shell subprocess with umask 077; it never changes the test
runner's process-wide umask. Hard-link regressions check both Cargo output and
destination rejection, preserved alias contents/identity, and staging cleanup.
The comma-TMPDIR regression also uses a fresh child and real Cargo: it checks the
raw output is singly-linked, final bytes equal raw WASM plus metadata, and signed
loading retains the expected ABI/declarations. A real rustc option failure must
preserve the previous signed artifact and leave no staging files or crate.
