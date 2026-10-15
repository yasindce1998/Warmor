# CI test kernels

The LSM integration tests boot kernels in a VM with [vimto](https://github.com/lmb/vimto).
The prebuilt [ci-kernels](https://github.com/cilium/ci-kernels) images cover
most tests, but they are built without IMA, so the exec integrity tests
(`internal/ebpf/integrity_integration_test.go`) would only ever skip on them.
`scripts/build-ci-kernel.sh` builds the same configuration with IMA added.

| File | Source |
|------|--------|
| `ci-kernels-config`, `ci-kernels-config-x86_64` | Copied unmodified from cilium/ci-kernels `build/` at commit `3efe27c03eff8cca34de52af4354dd66c6892bf0` (MIT licensed) |
| `config-warmor` | Warmor's additions: IMA with SHA-256, BPF LSM |

The build starts from `defconfig` with every module disabled, merges the three
files, sets the default LSM list (vimto cannot pass `lsm=` on the command
line), and fails if any requested option did not take effect, for example
because a dependency is missing on that kernel version.

```bash
scripts/build-ci-kernel.sh 6.18.53 /tmp/kernel-6.18
# vimto needs an absolute path: it resolves it from the test's package dir
vimto -kernel /tmp/kernel-6.18/vmlinuz -- go test -tags integration ./internal/ebpf/
```

To update the ci-kernels snippets, copy them again from a newer commit and
update the commit above.
