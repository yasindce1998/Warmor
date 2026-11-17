package wasm

import (
	"context"
	"time"

	wazeroapi "github.com/tetratelabs/wazero/api"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

// FieldsUnknown is the fields-read mask of a policy that did not declare
// which event fields its decisions depend on.
const FieldsUnknown = compiler.FieldsUnknown

// numEventTypes is the number of event types of the binary ABI.
const numEventTypes = 3

// fieldsReadTimeout bounds the declaration call made at pool creation.
const fieldsReadTimeout = time.Second

// readFieldsDeclaration queries the module's compiler.FieldsReadExport, if
// any. Anything other than a clean answer (no export, trap, timeout) yields
// FieldsUnknown, which disables every optimisation that relies on it.
func readFieldsDeclaration(ctx context.Context, p *Policy) [numEventTypes]uint32 {
	var out [numEventTypes]uint32
	for i := range out {
		out[i] = FieldsUnknown
	}
	fn := p.instance.ExportedFunction(compiler.FieldsReadExport)
	if fn == nil {
		return out
	}
	def := fn.Definition()
	if !hasSignature(def, []wazeroapi.ValueType{i32}, []wazeroapi.ValueType{i32}) {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, fieldsReadTimeout)
	defer cancel()
	for i := range out {
		res, err := fn.Call(ctx, uint64(i))
		if err != nil {
			// A trap can mutate guest state without closing it. The pool must
			// not reuse a partially initialized instance after a failed call.
			_ = p.instance.Close(ctx)
			for j := range out {
				out[j] = FieldsUnknown
			}
			return out
		}
		out[i] = uint32(res[0])
	}
	return out
}

// FieldsRead returns the declared mask (compiler.FieldBit*) of event fields
// the policy's decision for events of type t can depend on, or
// FieldsUnknown if the policy made no (usable) declaration.
func (p *Pool) FieldsRead(t api.EventType) uint32 {
	if t < 0 || int(t) >= numEventTypes {
		return FieldsUnknown
	}
	return p.fields[t]
}

// FieldsRead reports the evaluator's policy fields-read declaration; see
// Pool.FieldsRead.
func (e *PolicyEvaluator) FieldsRead(t api.EventType) uint32 {
	if e == nil || e.pool == nil {
		return FieldsUnknown
	}
	return e.pool.FieldsRead(t)
}

// RequiresCompleteCapture reports whether the policy declared, through the
// fields-read declaration bit, that it needs complete capture for the fields
// it reads. It is a worker observation of NEED only: the host never treats it
// as proof of input completeness.
func (e *PolicyEvaluator) RequiresCompleteCapture(t api.EventType) bool {
	f := e.FieldsRead(t)
	return f != FieldsUnknown && f&policymeta.FieldBitRequireCompleteCapture != 0
}

// RequiredCaptureFields returns the capturable fields this policy declared it
// needs complete. Completeness itself is computed by the host from the event,
// never from this declaration.
func (e *PolicyEvaluator) RequiredCaptureFields(t api.EventType) uint32 {
	return policymeta.RequiredCaptureFields(e.FieldsRead(t))
}
