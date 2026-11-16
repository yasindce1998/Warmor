package wasmtest

import "bytes"

// InitializationLoopPolicy has valid ABI exports but never returns from the
// initialization-time abi_version call. It is not compiler-workload padding.
func InitializationLoopPolicy() []byte {
	return assemble(mallocFn,
		fn{export: "evaluate_event", body: i32Const(0)},
		fn{export: "abi_version", noArg: true, body: []byte{opLoop, opBlockVoid, opBr, 0, opEnd, opI32Const, 5}})
}

// DeclaredPolicy is a constant ABI-5 policy with finite field declarations and
// complete empty process/network static domains. Intended only for fake-kernel
// lifecycle tests; it is not an artifact-provenance attestation.
func DeclaredPolicy(action int32) []byte {
	m := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	m = append(m, section(1, vec(
		[]byte{0x60, 1, typeI32, 1, typeI32},
		[]byte{0x60, 0, 1, typeI32},
		[]byte{0x60, 3, typeI32, typeI32, typeI32, 1, typeI32},
	))...)
	m = append(m, section(3, []byte{5, 0, 0, 1, 0, 2})...)
	m = append(m, section(5, []byte{1, 0, 1})...)
	exports := [][]byte{append(name("memory"), 2, 0)}
	for i, n := range []string{"malloc", "evaluate_event", "abi_version", "warmor_fields_read", "warmor_static_rules"} {
		exports = append(exports, append(name(n), 0, byte(i)))
	}
	m = append(m, section(7, vec(exports...))...)
	var code [][]byte
	malloc := append(i32Const(1024), i32Const(4096)...)
	malloc = append(malloc, opLocalGet, 0)
	malloc = append(malloc, i32Const(256)...)
	malloc = append(malloc, opI32Eq, opSelect)
	for _, instructions := range [][]byte{malloc, i32Const(action), i32Const(5), i32Const(0), i32Const(1)} {
		body := append([]byte{0}, instructions...)
		body = append(body, opEnd)
		code = append(code, append(uleb(uint32(len(body))), body...))
	}
	m = append(m, section(10, vec(code...))...)
	// malloc's buffer begins with the eligible byte; the optional static
	// export is pure and returns the one-byte table size for either domain.
	data := append([]byte{1, 0}, i32Const(4096)...)
	data = append(data, opEnd, 1, 1)
	return append(m, section(11, data)...)
}

// CompileHeavy forces real validation/SSA compilation under admission limits.
// It does not substitute guest loops or NOP padding for compiler work.
func CompileHeavy() []byte {
	const functions = 384
	m := append([]byte{0, 97, 115, 109, 1, 0, 0, 0}, section(1, []byte{1, 0x60, 0, 0})...)
	m = append(m, section(3, append(uleb(functions), make([]byte, functions)...))...)
	body := append([]byte{1, 1, 0x7f}, bytes.Repeat([]byte{0x20, 0, 0x41, 1, 0x6a, 0x21, 0, 0x20, 0, 0x04, 0x40, 0x20, 0, 0x41, 2, 0x6c, 0x21, 0, 0x0b}, 1024)...)
	body = append(body, opEnd)
	code := uleb(functions)
	for range functions {
		code = append(code, uleb(uint32(len(body)))...)
		code = append(code, body...)
	}
	return append(m, section(10, code)...)
}
