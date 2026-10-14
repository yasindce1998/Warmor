// Package wasmtest hand-assembles tiny binary-ABI policy modules for tests,
// so behaviour such as infinite loops or fields-read declarations can be
// exercised without the Rust toolchain. It is only imported from tests.
package wasmtest

// Opcodes and encodings used by the assembled modules.
const (
	opBlockVoid = 0x40
	opLoop      = 0x03
	opBr        = 0x0c
	opEnd       = 0x0b
	opLocalGet  = 0x20
	opI32Load   = 0x28
	opI32Const  = 0x41
	opI32Eqz    = 0x45
	opI32Eq     = 0x46
	opSelect    = 0x1b
	opMemGrow   = 0x40
	opDrop      = 0x1a
	typeI32     = 0x7f
)

func uleb(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func sleb(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func i32Const(v int32) []byte { return append([]byte{opI32Const}, sleb(v)...) }

func section(id byte, body []byte) []byte {
	return append(append([]byte{id}, uleb(uint32(len(body)))...), body...)
}

func vec(items ...[]byte) []byte {
	out := uleb(uint32(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func name(s string) []byte { return append(uleb(uint32(len(s))), s...) }

// fn is one exported function taking one i32 and returning one i32.
type fn struct {
	export string
	body   []byte // instructions, without the trailing end
}

// assemble builds a module with one page of memory (exported as "memory")
// and the given (i32) -> i32 functions, all exported.
func assemble(fns ...fn) []byte {
	mod := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	mod = append(mod, section(1, vec([]byte{0x60, 0x01, typeI32, 0x01, typeI32}))...)
	typeIdx := make([][]byte, len(fns))
	for i := range fns {
		typeIdx[i] = uleb(0)
	}
	mod = append(mod, section(3, vec(typeIdx...))...)
	mod = append(mod, section(5, vec([]byte{0x00, 0x01}))...) // memory: min 1 page
	exports := [][]byte{append(name("memory"), 0x02, 0x00)}
	for i, f := range fns {
		exports = append(exports, append(append(name(f.export), 0x00), uleb(uint32(i))...))
	}
	mod = append(mod, section(7, vec(exports...))...)
	codes := make([][]byte, len(fns))
	for i, f := range fns {
		body := append([]byte{0x00}, f.body...) // no locals
		body = append(body, opEnd)
		codes[i] = append(uleb(uint32(len(body))), body...)
	}
	return append(mod, section(10, vec(codes...))...)
}

// mallocFn always hands out the same buffer; enough for the binary ABI,
// which allocates its event buffer once per instance.
var mallocFn = fn{"malloc", i32Const(1024)}

// fieldsReadFn returns masks[event_type], or all-ones for other types.
func fieldsReadFn(masks [3]uint32) fn {
	var b []byte
	b = append(b, i32Const(int32(masks[0]))...)
	b = append(b, i32Const(int32(masks[1]))...)
	b = append(b, i32Const(int32(masks[2]))...)
	b = append(b, i32Const(-1)...)
	b = append(b, opLocalGet, 0x00)
	b = append(b, i32Const(2)...)
	b = append(b, opI32Eq, opSelect)
	b = append(b, opLocalGet, 0x00)
	b = append(b, i32Const(1)...)
	b = append(b, opI32Eq, opSelect)
	b = append(b, opLocalGet, 0x00, opI32Eqz, opSelect)
	return fn{"warmor_fields_read", b}
}

func withFields(evaluate fn, masks *[3]uint32) []byte {
	fns := []fn{mallocFn, evaluate}
	if masks != nil {
		fns = append(fns, fieldsReadFn(*masks))
	}
	return assemble(fns...)
}

// ConstPolicy returns a binary-ABI module whose evaluate_event always
// returns action. If masks is non-nil the module also declares
// warmor_fields_read, returning masks[event_type].
func ConstPolicy(action int32, masks *[3]uint32) []byte {
	return withFields(fn{"evaluate_event", i32Const(action)}, masks)
}

// UIDPolicy denies (1) events with uid 0 and allows (0) everything else.
func UIDPolicy(masks *[3]uint32) []byte {
	var b []byte
	b = append(b, i32Const(1)...)
	b = append(b, i32Const(0)...)
	b = append(b, opLocalGet, 0x00, opI32Load, 0x02, 0x04) // uid at offset 4
	b = append(b, opI32Eqz, opSelect)
	return withFields(fn{"evaluate_event", b}, masks)
}

// LoopPolicy never returns from evaluate_event.
func LoopPolicy() []byte {
	b := []byte{opLoop, opBlockVoid, opBr, 0x00, opEnd}
	b = append(b, i32Const(0)...)
	return withFields(fn{"evaluate_event", b}, nil)
}

// GrowPolicy tries to grow memory by pages and denies (1) if the growth was
// refused, allowing (0) otherwise.
func GrowPolicy(pages int32) []byte {
	var b []byte
	b = append(b, i32Const(1)...)
	b = append(b, i32Const(0)...)
	b = append(b, i32Const(pages)...)
	b = append(b, opMemGrow, 0x00)
	b = append(b, i32Const(-1)...)
	b = append(b, opI32Eq, opSelect)
	return withFields(fn{"evaluate_event", b}, nil)
}

// LoopOnUIDPolicy loops forever for uid 0 and allows everything else, so a
// test can time out one evaluation and then check the pool still works.
func LoopOnUIDPolicy() []byte {
	var b []byte
	b = append(b, opLocalGet, 0x00, opI32Load, 0x02, 0x04, opI32Eqz)
	b = append(b, 0x04, opBlockVoid) // if
	b = append(b, opLoop, opBlockVoid, opBr, 0x00, opEnd)
	b = append(b, opEnd) // end if
	b = append(b, i32Const(0)...)
	return withFields(fn{"evaluate_event", b}, nil)
}

// PathPrefixPolicy denies (1) events whose primary string (exec filename,
// file path or remote address) starts with the 4-byte prefix and allows (0)
// everything else.
func PathPrefixPolicy(prefix string, masks *[3]uint32) []byte {
	if len(prefix) != 4 {
		panic("wasmtest: prefix must be exactly 4 bytes")
	}
	want := int32(uint32(prefix[0]) | uint32(prefix[1])<<8 | uint32(prefix[2])<<16 | uint32(prefix[3])<<24)
	var b []byte
	b = append(b, i32Const(1)...)
	b = append(b, i32Const(0)...)
	b = append(b, opLocalGet, 0x00, opI32Load, 0x00, 77) // primary_str at offset 77
	b = append(b, i32Const(want)...)
	b = append(b, opI32Eq, opSelect)
	return withFields(fn{"evaluate_event", b}, masks)
}
