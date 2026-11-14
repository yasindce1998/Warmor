// Package policybuild stores artifact-author-approved build declarations in a
// WASM custom section. These are authenticated by the artifact signature, not
// proof of compiler provenance or a semantic analysis of arbitrary WASM.
package policybuild

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const Section = "warmor.build.v1"

type Metadata struct {
	Compiler      string `json:"compiler"`
	DefaultAction string `json:"default_action"`
}

func varint(b []byte) (uint32, int, error) {
	v, n := binary.Uvarint(b)
	if n <= 0 || n > 5 || v > 1<<32-1 {
		return 0, 0, errors.New("invalid WASM u32 length")
	}
	return uint32(v), n, nil
}

// Read rejects duplicate/malformed declarations and bounds all section reads.
// A missing declaration is acceptable only for legacy, non-assignment mode.
func Read(wasm []byte) (*Metadata, error) {
	if len(wasm) < 8 || !bytes.Equal(wasm[:8], []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
		return nil, errors.New("invalid WASM header")
	}
	var found *Metadata
	for pos := 8; pos < len(wasm); {
		id := wasm[pos]
		pos++
		size, n, err := varint(wasm[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		if uint64(size) > uint64(len(wasm)-pos) {
			return nil, errors.New("truncated WASM section")
		}
		data := wasm[pos : pos+int(size)]
		pos += int(size)
		if id != 0 {
			continue
		}
		nameSize, n, err := varint(data)
		if err != nil {
			return nil, err
		}
		if uint64(nameSize) > uint64(len(data)-n) {
			return nil, errors.New("truncated custom section")
		}
		if string(data[n:n+int(nameSize)]) != Section {
			continue
		}
		if found != nil {
			return nil, errors.New("duplicate build metadata")
		}
		payload := data[n+int(nameSize):]
		if len(payload) > 4096 {
			return nil, errors.New("build metadata too large")
		}
		var m Metadata
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, err
		}
		canonical, err := json.Marshal(m)
		if err != nil || !bytes.Equal(payload, canonical) || m.Compiler == "" || len(m.Compiler) > 256 || (m.DefaultAction != "allow" && m.DefaultAction != "deny" && m.DefaultAction != "log") {
			return nil, errors.New("invalid build metadata")
		}
		found = &m
	}
	return found, nil
}

// Append must run before artifact signing. It never edits signed bytes in place.
func Append(wasm []byte, m Metadata) ([]byte, error) {
	old, err := Read(wasm)
	if err != nil {
		return nil, err
	}
	if old != nil {
		return nil, errors.New("build metadata already present")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	section := binary.AppendUvarint(nil, uint64(len(Section)))
	section = append(section, Section...)
	section = append(section, payload...)
	out := append(bytes.Clone(wasm), 0)
	out = binary.AppendUvarint(out, uint64(len(section)))
	out = append(out, section...)
	if _, err := Read(out); err != nil {
		return nil, fmt.Errorf("build metadata: %w", err)
	}
	return out, nil
}
