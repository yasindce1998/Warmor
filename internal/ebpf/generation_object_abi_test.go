//go:build linux

package ebpf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type generationABIField struct {
	name, kind string
	offset     uint32
}

// Parse every ELF, including the non-native endian objects that build tags do
// not embed. CI runs this after regeneration with Clang 18 and Clang 21. No map
// or program is loaded: an unsized BTF FWD must fail the parser, not be skipped.
func TestGenerationObjectABI(t *testing.T) {
	dir := os.Getenv("WARMOR_BPF_ABI_DIR")
	if dir == "" {
		dir = "."
	}
	for _, hook := range []string{"exec", "file", "connect", "bind", "listen", "ptrace", "mount", "integrity"} {
		for _, endian := range []string{"el", "eb"} {
			t.Run(hook+"/"+endian, func(t *testing.T) {
				path := filepath.Join(dir, "lsm_"+hook+"_bpf"+endian+".o")
				object, err := elf.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				wantOrder := binary.ByteOrder(binary.LittleEndian)
				if endian == "eb" {
					wantOrder = binary.BigEndian
				}
				if object.Machine != elf.EM_BPF || object.ByteOrder != wantOrder {
					t.Errorf("wrong ELF target: machine=%v order=%v", object.Machine, object.ByteOrder)
				}
				if err := object.Close(); err != nil {
					t.Fatal(err)
				}
				spec, err := ebpf.LoadCollectionSpec(path)
				if err != nil {
					t.Fatal(err)
				}
				outer := spec.Maps["active_generation"]
				if outer == nil || outer.Type != ebpf.ArrayOfMaps || outer.KeySize != 4 || outer.ValueSize != 4 || outer.MaxEntries != 1 || len(outer.Contents) != 0 {
					t.Fatalf("not an empty single-pointer generation map: %+v", outer)
				}
				inner := outer.InnerMap
				want := generationMapSpec()
				if inner == nil || inner.Type != want.Type || inner.KeySize != 288 || inner.ValueSize != 16 || inner.MaxEntries != want.MaxEntries || inner.Flags != want.Flags {
					t.Fatalf("generation template ABI drift: %+v", inner)
				}
				var mapType *btf.Struct
				if err := spec.Types.TypeByName("generation_policy_map", &mapType); err != nil {
					t.Fatal(err)
				}
				foundValue := false
				for _, member := range mapType.Members {
					if member.Name == "value" {
						foundValue = true
						pointer, ok := member.Type.(*btf.Pointer)
						if !ok {
							t.Fatalf("generation map value is not a type pointer: %v", member.Type)
						}
						value, ok := pointer.Target.(*btf.Typedef)
						if !ok || value.Name != "generation_value" {
							t.Fatalf("map must use the canonical generation_value typedef: %v", pointer.Target)
						}
						underlying, ok := value.Type.(*btf.Struct)
						if !ok || underlying.Name != "" {
							t.Fatalf("generation value must remain anonymous for Clang 21 BTF: %v", value.Type)
						}
					}
				}
				if !foundValue {
					t.Fatal("generation inner map has no canonical value type")
				}
				checkGenerationStructABI(t, inner.Key, 288, generationKeyFields)
				value := checkGenerationStructABI(t, inner.Value, 16, []generationABIField{{"policy", "struct:8", 0}, {"generation", "u64", 8}})
				checkGenerationStructABI(t, value.Members[0].Type, 8, generationPolicyFields)
				legacy := spec.Maps["policy_map"]
				if legacy == nil || legacy.KeySize != 288 || legacy.ValueSize != 8 {
					t.Fatalf("legacy exact map ABI drift: %+v", legacy)
				}
				checkGenerationStructABI(t, legacy.Key, 288, generationKeyFields)
				checkGenerationStructABI(t, legacy.Value, 8, generationPolicyFields)
				var event *btf.Struct
				if err := spec.Types.TypeByName("warmor_event", &event); err != nil {
					t.Fatal(err)
				}
				checkGenerationStructABI(t, event, 416, generationEventFields)
				valueType, err := spec.Types.AnyTypeByName("generation_value")
				if err != nil {
					t.Fatal(err)
				}
				checkGenerationStructABI(t, valueType, 16, []generationABIField{{"policy", "struct:8", 0}, {"generation", "u64", 8}})
			})
		}
	}
}

var generationKeyFields = []generationABIField{
	{"cgroup_id", "u64", 0}, {"event_type", "u8", 8}, {"family", "u8", 9},
	{"port", "[2]u8", 10}, {"address", "[16]u8", 12}, {"path", "[256]s8", 28}, {"pad", "[4]u8", 284},
}

var generationPolicyFields = []generationABIField{
	{"action", "u8", 0}, {"audit", "u8", 1}, {"pad", "u16", 2}, {"hit_count", "u32", 4},
}

var generationEventFields = []generationABIField{
	{"pid", "u32", 0}, {"uid", "u32", 4}, {"gid", "u32", 8}, {"comm", "[16]s8", 12},
	{"filename", "[256]s8", 28}, {"timestamp", "u64", 288}, {"cgroup_id", "u64", 296},
	{"event_type", "u8", 304}, {"decision", "u8", 305}, {"remote_port", "u16", 306},
	{"remote_addr_v4", "u32", 308}, {"remote_addr_v6", "[16]u8", 312}, {"family", "u16", 328},
	{"pad", "[3]u16", 330}, {"aux", "[64]s8", 336}, {"aux_id", "u64", 400}, {"policy_generation", "u64", 408},
}

func checkGenerationStructABI(t *testing.T, typ btf.Type, size uint32, fields []generationABIField) *btf.Struct {
	t.Helper()
	s, ok := btf.UnderlyingType(typ).(*btf.Struct)
	if !ok || s.Size != size || len(s.Members) != len(fields) {
		t.Fatalf("wrong complete struct layout: %v, want size=%d members=%d", typ, size, len(fields))
	}
	for i, field := range fields {
		member := s.Members[i]
		if member.Name != field.name || member.Offset != btf.Bits(field.offset*8) || member.BitfieldSize != 0 || generationABIKind(member.Type) != field.kind {
			t.Errorf("%s field %d: %+v type=%s, want %+v", s.Name, i, member, generationABIKind(member.Type), field)
		}
	}
	return s
}

func generationABIKind(typ btf.Type) string {
	switch typ := btf.UnderlyingType(typ).(type) {
	case *btf.Int:
		prefix := "u"
		if typ.Encoding == btf.Signed || typ.Encoding == btf.Char {
			prefix = "s"
		}
		return fmt.Sprintf("%s%d", prefix, typ.Size*8)
	case *btf.Array:
		return fmt.Sprintf("[%d]%s", typ.Nelems, generationABIKind(typ.Type))
	case *btf.Struct:
		return fmt.Sprintf("struct:%d", typ.Size)
	default:
		return fmt.Sprintf("unsupported:%T", typ)
	}
}

func TestGenerationObjectGoABI(t *testing.T) {
	for _, tc := range []struct {
		value any
		size  int
	}{
		{PolicyKey{}, 288}, {PolicyValue{}, 8}, {generationValue{}, 16}, {LSMEvent{}, 416},
	} {
		if got := binary.Size(tc.value); got != tc.size || int(reflect.TypeOf(tc.value).Size()) != tc.size {
			t.Fatalf("%T binary/native size = %d/%d, want %d", tc.value, got, reflect.TypeOf(tc.value).Size(), tc.size)
		}
	}
	for _, tc := range []struct {
		value  any
		field  string
		offset uintptr
	}{
		{generationValue{}, "Policy", 0}, {generationValue{}, "Generation", 8},
		{LSMEvent{}, "Timestamp", 288}, {LSMEvent{}, "CgroupID", 296}, {LSMEvent{}, "PolicyGeneration", 408},
	} {
		field, ok := reflect.TypeOf(tc.value).FieldByName(tc.field)
		if !ok || field.Offset != tc.offset {
			t.Errorf("%T.%s offset=%d, want %d", tc.value, tc.field, field.Offset, tc.offset)
		}
	}
}
