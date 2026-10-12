package winutil

import (
	"sort"
	"strings"
	"sync"
)

// maxReverseEntries bounds the DOS→NT cache learned from translated events.
const maxReverseEntries = 8192

// DevicePathMap translates NT device paths reported by the kernel
// ("\Device\HarddiskVolume3\Windows\System32\cmd.exe") into the drive-letter
// form policies are written in ("C:\Windows\System32\cmd.exe"), and back.
//
// The reverse direction matters for kernel enforcement: the eBPF programs
// hash the NT path, so a decision made on the DOS path must be mapped back
// to exactly the bytes the kernel saw. TranslateImage records its input, so
// Untranslate returns the original NT path for any image that was observed,
// and falls back to prefix substitution otherwise.
type DevicePathMap struct {
	mu      sync.RWMutex
	devices []deviceEntry // sorted longest device first

	reverse      map[string]string // lowercased DOS path → NT path
	reverseOrder []string          // FIFO eviction order for reverse
}

type deviceEntry struct {
	device string // "\Device\HarddiskVolume3"
	drive  string // "C:"
}

// NewDevicePathMap builds a map from drive letter → NT device name pairs,
// e.g. {"C:": `\Device\HarddiskVolume3`}.
func NewDevicePathMap(drives map[string]string) *DevicePathMap {
	m := &DevicePathMap{reverse: make(map[string]string)}
	m.SetDrives(drives)
	return m
}

// SetDrives replaces the drive mapping (drives can be mounted at runtime).
func (m *DevicePathMap) SetDrives(drives map[string]string) {
	entries := make([]deviceEntry, 0, len(drives))
	for drive, device := range drives {
		if drive == "" || device == "" {
			continue
		}
		entries = append(entries, deviceEntry{
			device: strings.TrimRight(device, `\`),
			drive:  strings.ToUpper(strings.TrimRight(drive, `\`)),
		})
	}
	// Longest device first so "\Device\HarddiskVolume10" wins over
	// "\Device\HarddiskVolume1"; ties broken by drive for determinism.
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].device) != len(entries[j].device) {
			return len(entries[i].device) > len(entries[j].device)
		}
		return entries[i].drive < entries[j].drive
	})
	m.mu.Lock()
	m.devices = entries
	m.mu.Unlock()
}

// Translate converts an NT path to its drive-letter form. Paths that do not
// start with a known device are returned with the "\??\" prefix stripped,
// or unchanged (UNC "\Device\Mup\..." stays as-is).
func (m *DevicePathMap) Translate(nt string) string {
	if nt == "" {
		return ""
	}
	return m.translate(nt)
}

// TranslateImage is Translate for process image paths: it also records the
// pair so Untranslate can return the exact NT path. Only images are
// recorded, since kernel keys are only ever built from images; recording
// file paths would evict them.
func (m *DevicePathMap) TranslateImage(nt string) string {
	dos := m.Translate(nt)
	if dos != nt {
		m.remember(dos, nt)
	}
	return dos
}

func (m *DevicePathMap) translate(nt string) string {
	// Win32 namespace prefix: "\??\C:\x" → "C:\x".
	if strings.HasPrefix(nt, `\??\`) {
		return nt[len(`\??\`):]
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.devices {
		if hasPrefixFold(nt, e.device) {
			rest := nt[len(e.device):]
			if rest == "" {
				return e.drive + `\`
			}
			if rest[0] == '\\' {
				return e.drive + rest
			}
		}
	}
	return nt
}

// Untranslate returns the NT path for a drive-letter path: the exact path
// observed by TranslateImage if there was one, else prefix substitution.
func (m *DevicePathMap) Untranslate(dos string) string {
	if dos == "" {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if nt, ok := m.reverse[strings.ToLower(dos)]; ok {
		return nt
	}
	if len(dos) >= 2 && dos[1] == ':' {
		drive := strings.ToUpper(dos[:2])
		for _, e := range m.devices {
			if e.drive == drive {
				return e.device + dos[2:]
			}
		}
	}
	return dos
}

func (m *DevicePathMap) remember(dos, nt string) {
	key := strings.ToLower(dos)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.reverse[key]; !ok {
		m.reverseOrder = append(m.reverseOrder, key)
		if len(m.reverseOrder) > maxReverseEntries {
			oldest := m.reverseOrder[0]
			m.reverseOrder = m.reverseOrder[1:]
			delete(m.reverse, oldest)
		}
	}
	m.reverse[key] = nt
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
