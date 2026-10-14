//go:build linux

package ebpf

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type digest_key -type integrity_config lsm_integrity ../../bpf/lsm_integrity.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

// IntegrityMode selects what lsm_integrity does with a binary whose SHA-256
// is not in the allowlist. The values match INTEGRITY_MODE_* in the BPF code.
type IntegrityMode uint32

const (
	IntegrityOff     IntegrityMode = 0
	IntegrityAudit   IntegrityMode = 1
	IntegrityEnforce IntegrityMode = 2
)

// ParseIntegrityMode parses the --integrity-mode flag value.
func ParseIntegrityMode(s string) (IntegrityMode, error) {
	switch s {
	case "", "off":
		return IntegrityOff, nil
	case "audit":
		return IntegrityAudit, nil
	case "enforce":
		return IntegrityEnforce, nil
	}
	return IntegrityOff, fmt.Errorf("invalid integrity mode %q (valid: off, audit, enforce)", s)
}

func (m IntegrityMode) String() string {
	switch m {
	case IntegrityOff:
		return "off"
	case IntegrityAudit:
		return "audit"
	case IntegrityEnforce:
		return "enforce"
	}
	return fmt.Sprintf("IntegrityMode(%d)", uint32(m))
}

// ErrIMAUnavailable is returned by EnableIntegrity on kernels without IMA.
var ErrIMAUnavailable = errors.New("IMA unavailable")

// Digest is a SHA-256 file digest.
type Digest [32]byte

// ParseDigest decodes a hex SHA-256 digest.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	b, err := hex.DecodeString(s)
	if err != nil {
		return d, fmt.Errorf("decode sha256 %q: %w", s, err)
	}
	if len(b) != len(d) {
		return d, fmt.Errorf("sha256 %q: got %d bytes, want %d", s, len(b), len(d))
	}
	copy(d[:], b)
	return d, nil
}

// IntegrityStats are the lsm_integrity counters, summed across CPUs.
type IntegrityStats struct {
	CacheHits  uint64 // verdict reused from inode storage
	Hashed     uint64 // file hashed with IMA
	Denied     uint64 // exec refused (enforce) or reported (audit)
	HashErrors uint64 // IMA could not produce a SHA-256 digest
	// LastHashAlgo is the last value bpf_ima_file_hash returned: an enum
	// hash_algo (4 = SHA-256; 2 = SHA-1 means IMA's default hash is not
	// SHA-256 and every exec fails closed) or a negative errno.
	LastHashAlgo int64
}

// integrityProgram owns the lsm_integrity objects and link. It is loaded on
// demand by EnableIntegrity because it needs a sleepable BPF LSM hook, IMA
// and inode storage, which kernels without CONFIG_IMA do not provide; users
// who never ask for integrity checking should not fail to start over it.
type integrityProgram struct {
	mu      sync.Mutex
	objs    *lsm_integrityObjects
	link    link.Link
	allowed map[Digest]struct{}
	gen     uint32
	mode    IntegrityMode
}

// EnableIntegrity loads and attaches lsm_integrity (once), installs digests
// as the allowlist and sets mode. It shares lsm_events and lsm_cgroup_filter
// with the other LSM programs, so denials arrive through ReadLSMEvent as
// EventTypeIntegrity and the --cgroup-filter scope applies.
func (l *LSMLoader) EnableIntegrity(digests []Digest, mode IntegrityMode) error {
	if l.integrity == nil {
		ok, err := imaAvailable()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: exec integrity hashes files with IMA, but this kernel "+
				"was built without CONFIG_IMA", ErrIMAUnavailable)
		}
		objs := &lsm_integrityObjects{}
		opts := &ciliumebpf.CollectionOptions{
			MapReplacements: map[string]*ciliumebpf.Map{
				"lsm_events":        l.execObjs.LsmEvents,
				"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
				// Unused by lsm_integrity but declared in warmor_lsm.h;
				// share them so loading doesn't allocate duplicates.
				"policy_map":  l.execObjs.PolicyMap,
				"lsm_enforce": l.execObjs.LsmEnforce,
			},
		}
		if err := loadLsm_integrityObjects(objs, opts); err != nil {
			return fmt.Errorf("load lsm_integrity (needs CONFIG_IMA and a sleepable BPF LSM, kernel 5.18+): %w", err)
		}
		lnk, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmIntegrityCheck})
		if err != nil {
			objs.Close()
			return fmt.Errorf("attach lsm.s/bprm_check_security: %w", err)
		}
		l.integrity = &integrityProgram{objs: objs, link: lnk, allowed: make(map[Digest]struct{})}
	}

	p := l.integrity
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.setAllowlist(digests); err != nil {
		return err
	}
	return p.setMode(mode)
}

// SetIntegrityAllowlist replaces the allowlist. The program must have been
// enabled first.
func (l *LSMLoader) SetIntegrityAllowlist(digests []Digest) error {
	if l.integrity == nil {
		return errors.New("integrity checking is not enabled")
	}
	l.integrity.mu.Lock()
	defer l.integrity.mu.Unlock()
	return l.integrity.setAllowlist(digests)
}

// SetIntegrityMode changes the mode without touching the allowlist.
func (l *LSMLoader) SetIntegrityMode(mode IntegrityMode) error {
	if l.integrity == nil {
		if mode == IntegrityOff {
			return nil
		}
		return errors.New("integrity checking is not enabled")
	}
	l.integrity.mu.Lock()
	defer l.integrity.mu.Unlock()
	return l.integrity.setMode(mode)
}

// IntegrityStats returns the kernel counters, or zero stats when disabled.
func (l *LSMLoader) IntegrityStats() (IntegrityStats, error) {
	var s IntegrityStats
	if l.integrity == nil {
		return s, nil
	}
	m := l.integrity.objs.IntegrityStats
	for idx, dst := range []*uint64{&s.CacheHits, &s.Hashed, &s.Denied, &s.HashErrors} {
		var perCPU []uint64
		if err := m.Lookup(uint32(idx), &perCPU); err != nil {
			return s, fmt.Errorf("read integrity stat %d: %w", idx, err)
		}
		for _, v := range perCPU {
			*dst += v
		}
	}
	// Per-CPU "last value": take any CPU that has run the program.
	var perCPU []uint64
	if err := m.Lookup(uint32(4), &perCPU); err != nil {
		return s, fmt.Errorf("read integrity last algo: %w", err)
	}
	for _, v := range perCPU {
		if v != 0 {
			s.LastHashAlgo = int64(v)
		}
	}
	return s, nil
}

// setAllowlist makes the kernel allowlist equal to digests. The order matters
// because verdicts are cached per inode and only invalidated by a generation
// bump: new digests are added first, then removed ones deleted, and only then
// is the generation bumped. Bumping before the delete would let an exec in
// between cache "allowed" for a digest about to be removed under the new
// generation, and that stale verdict would survive until the file changed.
func (p *integrityProgram) setAllowlist(digests []Digest) error {
	want := make(map[Digest]struct{}, len(digests))
	for _, d := range digests {
		want[d] = struct{}{}
	}

	one := uint8(1)
	for d := range want {
		if _, ok := p.allowed[d]; ok {
			continue
		}
		key := lsm_integrityDigestKey{Digest: d}
		if err := p.objs.IntegrityAllow.Put(&key, &one); err != nil {
			return fmt.Errorf("add digest %x: %w", d, err)
		}
		p.allowed[d] = struct{}{}
	}
	for d := range p.allowed {
		if _, ok := want[d]; ok {
			continue
		}
		key := lsm_integrityDigestKey{Digest: d}
		if err := p.objs.IntegrityAllow.Delete(&key); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			return fmt.Errorf("remove digest %x: %w", d, err)
		}
		delete(p.allowed, d)
	}

	p.gen++
	return p.writeConfig()
}

func (p *integrityProgram) setMode(mode IntegrityMode) error {
	if mode > IntegrityEnforce {
		return fmt.Errorf("invalid integrity mode %d", mode)
	}
	p.mode = mode
	return p.writeConfig()
}

func (p *integrityProgram) writeConfig() error {
	cfg := lsm_integrityIntegrityConfig{Mode: uint32(p.mode), Generation: p.gen}
	if err := p.objs.IntegrityCfg.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("write integrity config: %w", err)
	}
	return nil
}

func (p *integrityProgram) close() error {
	var errs []error
	if p.link != nil {
		errs = append(errs, p.link.Close())
	}
	if p.objs != nil {
		errs = append(errs, p.objs.Close())
	}
	return errors.Join(errs...)
}

// imaAvailable reports whether the running kernel has IMA built in. Without
// CONFIG_IMA, bpf_ima_file_hash is a stub that always returns -EOPNOTSUPP,
// so lsm_integrity would fail every exec closed. The kernel's BTF only
// describes ima_file_hash when IMA is compiled in.
func imaAvailable() (bool, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false, fmt.Errorf("load kernel BTF: %w", err)
	}
	var fn *btf.Func
	if err := spec.TypeByName("ima_file_hash", &fn); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("look up ima_file_hash in kernel BTF: %w", err)
	}
	return true, nil
}
