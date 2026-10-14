package wasm

import (
	"context"
	"fmt"
	"slices"

	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"
)

// Policy ABI versions understood by this host. A module may declare the
// version it was written against by exporting `abi_version() -> i32`.
// Modules that do not export it are accepted for backward compatibility.
//
//	1  original single-event contract
//	2  adds the "type"-tagged multi-event JSON format (PROCESS/FILE/NETWORK)
//
// Both versions use the same wire format; the host rejects anything outside
// this range so a policy built for a future, incompatible contract fails
// loudly at load time instead of silently mis-evaluating every event.
const (
	MinABIVersion uint32 = 1
	MaxABIVersion uint32 = 2
)

// Export names that make up the host <-> policy contract.
const (
	exportEvaluateEvent   = "evaluate_event"   // binary ABI: (ptr i32) -> i32
	exportEvaluateSyscall = "evaluate_syscall" // JSON ABI:   (ptr i32, len i32) -> i32
	exportMalloc          = "malloc"
	exportABIVersion      = "abi_version"
)

var i32 = wazeroapi.ValueTypeI32

// policyABI describes which evaluation entry point a module provides.
type policyABI int

const (
	abiJSON policyABI = iota
	abiBinary
)

func hasSignature(def wazeroapi.FunctionDefinition, params, results []wazeroapi.ValueType) bool {
	return slices.Equal(def.ParamTypes(), params) && slices.Equal(def.ResultTypes(), results)
}

func signatureString(def wazeroapi.FunctionDefinition) string {
	name := func(ts []wazeroapi.ValueType) string {
		s := "("
		for i, t := range ts {
			if i > 0 {
				s += ", "
			}
			s += wazeroapi.ValueTypeName(t)
		}
		return s + ")"
	}
	return name(def.ParamTypes()) + " -> " + name(def.ResultTypes())
}

// detectABI picks the evaluation ABI from the module's export signatures and
// rejects modules whose exports cannot be called the way the host calls them.
//
// The binary ABI is selected only when evaluate_event has the binary
// signature (i32) -> i32. A module that exports evaluate_event with any other
// signature (e.g. the JSON-style (ptr, len)) falls back to evaluate_syscall if
// it has one, and is rejected otherwise: calling it with one argument would
// fail on every event and the host would deny everything.
func detectABI(exports map[string]wazeroapi.FunctionDefinition) (policyABI, error) {
	if _, ok := exports[exportMalloc]; !ok {
		return 0, fmt.Errorf("policy module does not export %q", exportMalloc)
	}

	if def, ok := exports[exportABIVersion]; ok && !hasSignature(def, nil, []wazeroapi.ValueType{i32}) {
		return 0, fmt.Errorf("policy export %q has signature %s, want () -> (i32)",
			exportABIVersion, signatureString(def))
	}

	evEvent, hasEvent := exports[exportEvaluateEvent]
	evSyscall, hasSyscall := exports[exportEvaluateSyscall]

	if hasEvent && hasSignature(evEvent, []wazeroapi.ValueType{i32}, []wazeroapi.ValueType{i32}) {
		return abiBinary, nil
	}
	if hasSyscall {
		if !hasSignature(evSyscall, []wazeroapi.ValueType{i32, i32}, []wazeroapi.ValueType{i32}) {
			return 0, fmt.Errorf("policy export %q has signature %s, want (i32, i32) -> (i32)",
				exportEvaluateSyscall, signatureString(evSyscall))
		}
		return abiJSON, nil
	}
	if hasEvent {
		return 0, fmt.Errorf("policy export %q has signature %s, but the binary ABI requires (i32) -> (i32); "+
			"JSON policies taking (ptr, len) must export %q instead",
			exportEvaluateEvent, signatureString(evEvent), exportEvaluateSyscall)
	}
	return 0, fmt.Errorf("policy module exports neither %q nor %q", exportEvaluateEvent, exportEvaluateSyscall)
}

// validateCompiledModule checks the module's exports statically.
func validateCompiledModule(compiled wazero.CompiledModule) error {
	_, err := detectABI(compiled.ExportedFunctions())
	return err
}

// checkABIVersion calls the optional abi_version export and rejects versions
// this host does not implement.
func checkABIVersion(ctx context.Context, instance wazeroapi.Module) error {
	fn := instance.ExportedFunction(exportABIVersion)
	if fn == nil {
		return nil
	}
	results, err := fn.Call(ctx)
	if err != nil {
		return fmt.Errorf("call %s: %w", exportABIVersion, err)
	}
	v := uint32(results[0])
	if v < MinABIVersion || v > MaxABIVersion {
		return fmt.Errorf("unsupported policy ABI version %d (this host supports %d-%d)",
			v, MinABIVersion, MaxABIVersion)
	}
	return nil
}

// initPolicy wraps a freshly instantiated module in a Policy, selecting its
// ABI and pre-allocating the binary event buffer where needed. On error the
// instance is closed.
func initPolicy(ctx context.Context, runtime *Runtime, instance wazeroapi.Module) (*Policy, error) {
	abi, err := detectABI(instance.ExportedFunctionDefinitions())
	if err != nil {
		instance.Close(ctx)
		return nil, err
	}

	p := &Policy{runtime: runtime, instance: instance}
	if abi == abiBinary {
		p.useBinaryABI = true
		results, err := instance.ExportedFunction(exportMalloc).Call(ctx, uint64(eventStructSize))
		if err != nil {
			instance.Close(ctx)
			return nil, fmt.Errorf("malloc for event buffer: %w", err)
		}
		p.eventBufPtr = uint32(results[0])
	}
	return p, nil
}
