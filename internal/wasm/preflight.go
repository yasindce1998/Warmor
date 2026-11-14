package wasm

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// These are admission limits, not a compiler sandbox or a WASM validator.
// Counts in a tiny malformed module can otherwise request gigabytes before
// wazero discovers that the section is truncated. Per-function/code limits
// also reduce (but cannot time-bound) adversarial compiler work. Keep these
// fixed for every load path, including cached/signed modules.
const (
	MaxPolicyFunctions     = 8192
	MaxPolicyFunctionBytes = 64 << 10
	MaxPolicyCodeBytes     = 8 << 20
	maxPolicyVector        = 16384
	maxPolicyEntities      = 65536
	maxPolicyLocals        = 4096
	maxPolicyTotalLocals   = 262144
	maxPolicyTypeArity     = 256
	maxPolicyTableElements = 65536
	maxPolicySections      = 256
)

// wasmCursor is a zero-copy, non-recursive framing reader. It never allocates
// according to guest-provided lengths. Full WASM semantic validation remains
// wazero's job; fail closed if framing/features here are not understood.
type wasmCursor []byte

func (r *wasmCursor) take(n uint32) (wasmCursor, error) {
	if uint64(n) > uint64(len(*r)) {
		return nil, io.ErrUnexpectedEOF
	}
	out := (*r)[:n]
	*r = (*r)[n:]
	return out, nil
}

func (r *wasmCursor) byte() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *wasmCursor) u32() (uint32, error) {
	var out uint32
	for i := 0; i < 5; i++ {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		if i == 4 && b > 0x0f {
			return 0, fmt.Errorf("invalid u32 length/index")
		}
		out |= uint32(b&0x7f) << (i * 7)
		if b&0x80 == 0 {
			return out, nil
		}
	}
	return 0, fmt.Errorf("invalid u32 length/index")
}

func (r *wasmCursor) name() (wasmCursor, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	return r.take(n)
}

type moduleBudget struct {
	entities, locals, tableElements uint64
}

func (b *moduleBudget) vector(r *wasmCursor, limit uint32) (uint32, error) {
	n, err := r.u32()
	if err != nil {
		return 0, err
	}
	b.entities += uint64(n)
	if n > limit || b.entities > maxPolicyEntities {
		return 0, fmt.Errorf("vector count %d exceeds policy complexity limit", n)
	}
	return n, nil
}

func preflightModule(ctx context.Context, binary []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(binary) > MaxPolicySize {
		return fmt.Errorf("module too large")
	}
	if len(binary) < 8 || !bytes.Equal(binary[:8], []byte{'\x00', 'a', 's', 'm', 1, 0, 0, 0}) {
		return fmt.Errorf("invalid WASM header")
	}
	r := wasmCursor(binary[8:])
	b := moduleBudget{}
	var seen uint16
	for sections := 0; len(r) != 0; sections++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sections >= maxPolicySections {
			return fmt.Errorf("too many module sections")
		}
		id, err := r.byte()
		if err != nil {
			return err
		}
		size, err := r.u32()
		if err != nil {
			return err
		}
		payload, err := r.take(size)
		if err != nil {
			return err
		}
		if id > 12 {
			return fmt.Errorf("unsupported section %d", id)
		}
		if id != 0 {
			if seen&(1<<id) != 0 {
				return fmt.Errorf("duplicate section %d", id)
			}
			seen |= 1 << id
		}
		if err := b.section(ctx, id, &payload); err != nil {
			return fmt.Errorf("section %d: %w", id, err)
		}
	}
	return ctx.Err()
}

func (b *moduleBudget) section(ctx context.Context, id byte, r *wasmCursor) error {
	if id == 0 {
		return b.custom(r)
	}
	if id == 8 || id == 12 { // start index / data count, not a vector
		_, err := r.u32()
		if err != nil {
			return err
		}
		if len(*r) != 0 {
			return fmt.Errorf("trailing bytes")
		}
		return nil
	}
	limit := uint32(maxPolicyVector)
	if id == 3 || id == 10 {
		limit = MaxPolicyFunctions
	}
	n, err := b.vector(r, limit)
	if err != nil {
		return err
	}
	if id == 10 && len(*r) > MaxPolicyCodeBytes {
		return fmt.Errorf("code exceeds %d bytes", MaxPolicyCodeBytes)
	}
	for i := uint32(0); i < n; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch id {
		case 1:
			form, err := r.byte()
			if err != nil {
				return err
			}
			if form != 0x60 {
				return fmt.Errorf("unsupported type form")
			}
			for j := 0; j < 2; j++ {
				arity, err := b.vector(r, maxPolicyTypeArity)
				if err != nil {
					return err
				}
				if _, err = r.take(arity); err != nil {
					return err
				}
			}
		case 2:
			if _, err := r.name(); err != nil {
				return err
			}
			if _, err := r.name(); err != nil {
				return err
			}
			kind, err := r.byte()
			if err != nil {
				return err
			}
			switch kind {
			case 0:
				_, err = r.u32()
			case 1:
				err = b.table(r)
			case 2:
				err = b.limits(r, false)
			case 3:
				_, err = r.take(2) // type, mutability
			default:
				return fmt.Errorf("unsupported import kind")
			}
			if err != nil {
				return err
			}
		case 3:
			if _, err := r.u32(); err != nil {
				return err
			}
		case 4:
			if err := b.table(r); err != nil {
				return err
			}
		case 5:
			if err := b.limits(r, false); err != nil {
				return err
			}
		case 6:
			if _, err := r.take(2); err != nil {
				return err
			}
			if err := r.constExpr(); err != nil {
				return err
			}
		case 7:
			if _, err := r.name(); err != nil {
				return err
			}
			if _, err := r.byte(); err != nil {
				return err
			}
			if _, err := r.u32(); err != nil {
				return err
			}
		case 9:
			if err := b.element(r); err != nil {
				return err
			}
		case 10:
			size, err := r.u32()
			if err != nil {
				return err
			}
			if size > MaxPolicyFunctionBytes {
				return fmt.Errorf("function body exceeds %d bytes", MaxPolicyFunctionBytes)
			}
			body, err := r.take(size)
			if err != nil {
				return err
			}
			groups, err := b.vector(&body, maxPolicyLocals)
			if err != nil {
				return err
			}
			var locals uint64
			for j := uint32(0); j < groups; j++ {
				count, err := body.u32()
				if err != nil {
					return err
				}
				locals += uint64(count)
				b.locals += uint64(count)
				if locals > maxPolicyLocals || b.locals > maxPolicyTotalLocals {
					return fmt.Errorf("local count exceeds policy complexity limit")
				}
				if _, err = body.byte(); err != nil {
					return err
				}
			}
			// Instructions are opaque: don't mistake immediate bytes for
			// opcodes or pretend to be a second full WASM validator.
		case 11:
			flags, err := r.u32()
			if err != nil {
				return err
			}
			if flags > 2 {
				return fmt.Errorf("unsupported data segment flags")
			}
			if flags == 2 {
				if _, err = r.u32(); err != nil {
					return err
				}
			}
			if flags != 1 {
				if err = r.constExpr(); err != nil {
					return err
				}
			}
			// Data payloads use the same length-prefix framing as names.
			if _, err = r.name(); err != nil {
				return err
			}
		}
	}
	if len(*r) != 0 {
		return fmt.Errorf("trailing section bytes")
	}
	return nil
}

func (b *moduleBudget) limits(r *wasmCursor, table bool) error {
	flags, err := r.byte()
	if err != nil {
		return err
	}
	if flags > 1 {
		return fmt.Errorf("unsupported shared/64-bit limits")
	}
	min, err := r.u32()
	if err != nil {
		return err
	}
	if table {
		b.tableElements += uint64(min)
		if b.tableElements > maxPolicyTableElements {
			return fmt.Errorf("table minimum exceeds policy complexity limit")
		}
	}
	if flags == 1 {
		_, err = r.u32()
	}
	return err
}

func (b *moduleBudget) table(r *wasmCursor) error {
	if _, err := r.byte(); err != nil {
		return err
	}
	return b.limits(r, true)
}

// constExpr frames the constant expressions supported by wazero 1.11, without
// allocating their values. Future WASM features must explicitly extend this.
func (r *wasmCursor) constExpr() error {
	op, err := r.byte()
	if err != nil {
		return err
	}
	switch op {
	case 0x41, 0x42: // signed integer LEBs (wazero validates their value/width)
		max := 5
		if op == 0x42 {
			max = 10
		}
		for i := 0; ; i++ {
			if i == max {
				return fmt.Errorf("invalid constant length")
			}
			v, err := r.byte()
			if err != nil {
				return err
			}
			if v&0x80 == 0 {
				break
			}
		}
	case 0x43:
		_, err = r.take(4)
	case 0x44:
		_, err = r.take(8)
	case 0x23, 0xd2:
		_, err = r.u32()
	case 0xd0:
		_, err = r.byte()
	case 0xfd:
		var suffix byte
		suffix, err = r.byte()
		if err == nil && suffix != 0x0c {
			return fmt.Errorf("unsupported vector constant")
		}
		if err == nil {
			_, err = r.take(16)
		}
	default:
		return fmt.Errorf("unsupported constant expression")
	}
	if err != nil {
		return err
	}
	end, err := r.byte()
	if err != nil {
		return err
	}
	if end != 0x0b {
		return fmt.Errorf("unterminated constant expression")
	}
	return nil
}

func (b *moduleBudget) element(r *wasmCursor) error {
	flags, err := r.u32()
	if err != nil {
		return err
	}
	if flags > 7 {
		return fmt.Errorf("unsupported element flags")
	}
	if flags == 2 || flags == 6 {
		if _, err = r.u32(); err != nil {
			return err
		}
	}
	if flags&1 == 0 {
		if err = r.constExpr(); err != nil {
			return err
		}
	}
	if flags != 0 && flags != 4 {
		if _, err = r.byte(); err != nil {
			return err
		}
	}
	n, err := b.vector(r, maxPolicyTableElements)
	if err != nil {
		return err
	}
	for i := uint32(0); i < n; i++ {
		if flags < 4 {
			_, err = r.u32()
		} else {
			err = r.constExpr()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *moduleBudget) custom(r *wasmCursor) error {
	name, err := r.name()
	if err != nil {
		return err
	}
	if !bytes.Equal(name, []byte("name")) {
		// Other custom payloads are opaque with DWARF decoding disabled.
		return nil
	}
	for subsections := 0; len(*r) > 0; subsections++ {
		if subsections >= maxPolicySections {
			return fmt.Errorf("too many name subsections")
		}
		id, err := r.byte()
		if err != nil {
			return err
		}
		size, err := r.u32()
		if err != nil {
			return err
		}
		payload, err := r.take(size)
		if err != nil {
			return err
		}
		switch id {
		case 0:
			if _, err = payload.name(); err != nil {
				return err
			}
		case 1, 2:
			n, err := b.vector(&payload, maxPolicyVector)
			if err != nil {
				return err
			}
			for i := uint32(0); i < n; i++ {
				if _, err = payload.u32(); err != nil {
					return err
				}
				if id == 1 {
					_, err = payload.name()
				} else {
					var locals uint32
					locals, err = b.vector(&payload, maxPolicyVector)
					if err != nil {
						return err
					}
					for j := uint32(0); j < locals; j++ {
						if _, err = payload.u32(); err != nil {
							return err
						}
						if _, err = payload.name(); err != nil {
							return err
						}
					}
				}
				if err != nil {
					return err
				}
			}
		default:
			payload = nil // unknown subsections are skipped by wazero
		}
		// wazero's name decoder assumes exact subsection lengths. Don't
		// let it consume the next section as names after malformed framing.
		if len(payload) != 0 {
			return fmt.Errorf("trailing name subsection bytes")
		}
	}
	return nil
}
