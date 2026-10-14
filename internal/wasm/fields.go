package wasm

import (
	"context"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
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
	if len(def.ParamTypes()) != 1 || len(def.ResultTypes()) != 1 {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, fieldsReadTimeout)
	defer cancel()
	for i := range out {
		res, err := fn.Call(ctx, uint64(i))
		if err != nil {
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
