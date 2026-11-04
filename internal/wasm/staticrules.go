package wasm

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
)

// staticRulesTimeout bounds the declaration calls made at pool creation.
const staticRulesTimeout = 5 * time.Second

// StaticDomain is one event type's kernel default-deny declaration, read
// from the module's compiler.StaticRulesExport table: whether the domain is
// eligible (its policy-map entries can be a complete allowlist) and the
// rules to preload. See docs/design/kernel-default-deny.md.
type StaticDomain struct {
	Eligible bool
	Rules    []compiler.StaticRule
}

// readStaticDomain queries the module's static-rules table for one event
// type (0 process, 2 network). Anything other than a clean answer (no
// export, trap, timeout, malformed table) yields an ineligible domain, so
// the kernel keeps allowing misses — the safe default.
func readStaticDomain(ctx context.Context, p *Policy, eventType uint32) StaticDomain {
	var out StaticDomain

	fn := p.instance.ExportedFunction(compiler.StaticRulesExport)
	if fn == nil {
		return out
	}
	def := fn.Definition()
	if len(def.ParamTypes()) != 3 || len(def.ResultTypes()) != 1 {
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, staticRulesTimeout)
	defer cancel()

	// Size query first: cap=0 never writes to the null pointer.
	res, err := fn.Call(ctx, uint64(eventType), 0, 0)
	if err != nil || len(res) != 1 {
		return out
	}
	size := uint32(res[0])
	if size == 0 || size > 4<<20 {
		return out
	}

	malloc := p.instance.ExportedFunction("malloc")
	if malloc == nil {
		return out
	}
	res, err = malloc.Call(ctx, uint64(size))
	if err != nil || len(res) != 1 {
		return out
	}
	ptr := uint32(res[0])

	defer func() {
		if freeFn := p.instance.ExportedFunction("free"); freeFn != nil {
			_, _ = freeFn.Call(ctx, uint64(ptr), uint64(size))
		}
	}()

	res, err = fn.Call(ctx, uint64(eventType), uint64(ptr), uint64(size))
	if err != nil || len(res) != 1 || uint32(res[0]) != size {
		return out
	}
	data, ok := p.instance.Memory().Read(ptr, size)
	if !ok {
		return out
	}

	rules, eligible, err := parseStaticTable(data, eventType)
	if err != nil {
		return out
	}
	out.Rules = rules
	out.Eligible = eligible
	return out
}

// parseStaticTable decodes [eligible u8][entry]* where an entry is
// [action u8][audit u8][port u16][len u16][pattern bytes]. A zero eligible
// byte decodes as an ineligible domain with no rules and no error (the
// compiler emits it for domains the policy cannot make complete); a set
// byte with no entries is an eligible domain whose policy allows nothing.
func parseStaticTable(data []byte, eventType uint32) (rules []compiler.StaticRule, eligible bool, err error) {
	if len(data) < 1 {
		return nil, false, fmt.Errorf("empty table")
	}
	if data[0] == 0 {
		return nil, false, nil
	}
	eventName := "process"
	if eventType == 2 {
		eventName = "network"
	}

	i := 1
	for i < len(data) {
		if i+6 > len(data) {
			return nil, false, fmt.Errorf("truncated entry header at %d", i)
		}
		action := data[i]
		audit := data[i+1]
		port := binary.LittleEndian.Uint16(data[i+2 : i+4])
		plen := int(binary.LittleEndian.Uint16(data[i+4 : i+6]))
		i += 6
		if plen < 0 || i+plen > len(data) {
			return nil, false, fmt.Errorf("truncated pattern at %d", i)
		}
		pattern := string(data[i : i+plen])
		i += plen

		if action > 1 || audit > 1 {
			return nil, false, fmt.Errorf("invalid action/audit byte")
		}
		rules = append(rules, compiler.StaticRule{
			Event:   eventName,
			Action:  action,
			Audit:   audit == 1,
			Pattern: pattern,
			Port:    port,
		})
	}
	return rules, true, nil
}

// StaticRulesProcess returns the process (exec) domain declaration.
func (p *Pool) StaticRulesProcess() StaticDomain { return p.staticProcess }

// StaticRulesNetwork returns the network (connect) domain declaration.
func (p *Pool) StaticRulesNetwork() StaticDomain { return p.staticNetwork }

// StaticRulesProcess reports the evaluator's process domain declaration.
func (e *PolicyEvaluator) StaticRulesProcess() StaticDomain {
	if e == nil || e.pool == nil {
		return StaticDomain{}
	}
	return e.pool.StaticRulesProcess()
}

// StaticRulesNetwork reports the evaluator's network domain declaration.
func (e *PolicyEvaluator) StaticRulesNetwork() StaticDomain {
	if e == nil || e.pool == nil {
		return StaticDomain{}
	}
	return e.pool.StaticRulesNetwork()
}
