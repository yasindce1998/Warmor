package wasm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestABIV6_JSONQualityCarriage(t *testing.T) {
	event := &api.Event{Comm: "bash", TruncatedFields: []string{"filename", "process.args", "mystery"}}
	data, err := marshalEventForWASM(event, CaptureQualityABIVersion)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	quality, ok := doc["capture_quality"].(map[string]any)
	if !ok {
		t.Fatalf("ABI 6 JSON missing capture_quality: %s", data)
	}
	if quality["filename"] != string(api.CaptureStateTruncated) || quality["process.args"] != string(api.CaptureStateTruncated) {
		t.Fatalf("truncated states = %v", quality)
	}
	if _, exists := quality["mystery"]; exists {
		t.Fatal("unknown truncation name must not become a quality state")
	}
	if quality["parent_comm"] != string(api.CaptureStateUnknown) || quality["cgroup_id"] != string(api.CaptureStateUnknown) {
		t.Fatalf("unknown states = %v", quality)
	}

	// Modules declaring <= 5 never see the new key.
	for _, v := range []uint32{3, 4, 5} {
		old, err := marshalEventForWASM(event, v)
		if err != nil {
			t.Fatal(err)
		}
		var oldDoc map[string]any
		if err := json.Unmarshal(old, &oldDoc); err != nil {
			t.Fatal(err)
		}
		if _, exists := oldDoc["capture_quality"]; exists {
			t.Fatalf("ABI %d JSON unexpectedly carries capture_quality", v)
		}
	}
}

func TestABIV6_CaptureQualityHostCallback(t *testing.T) {
	live := &api.Event{
		KernelTimestampNS: 42, PPID: 0, ParentComm: "", CgroupID: 0,
		TruncatedFields: []string{"path"},
	}
	ctx := contextWithEvent(context.Background(), live)
	want := uint32(policymeta.FieldBitPPID | policymeta.FieldBitParentComm | policymeta.FieldBitCgroupID | policymeta.FieldBitPath)
	if got := hostGetFieldU32(ctx, nil, FieldCaptureQuality); got != want {
		t.Fatalf("quality mask = %#x, want %#x", got, want)
	}
	if got := hostGetFieldU32(ctx, nil, FieldPPID); got != live.PPID {
		t.Fatalf("ppid callback = %d, want %d", got, live.PPID)
	}

	// Replay/synthetic events without a trusted timestamp are not marked
	// incomplete merely for unset parent/cgroup fields.
	replay := &api.Event{PPID: 0, ParentComm: "", CgroupID: 0}
	if got := hostGetFieldU32(contextWithEvent(context.Background(), replay), nil, FieldCaptureQuality); got != 0 {
		t.Fatalf("replay quality mask = %#x, want 0", got)
	}
}

func TestDeclarationRoundTrip_RequireCompleteCaptureBit(t *testing.T) {
	mask := uint32(compiler.FieldBitPath | compiler.FieldBitPPID | compiler.FieldBitRequireCompleteCapture)
	rt, err := loadTestModule(t,
		fnMalloc, fnFree, fnJSONAllow,
		abiVersion(int32(CaptureQualityABIVersion)),
		testFunc{name: compiler.FieldsReadExport, params: 1, results: 1, ret: int32(mask)},
	)
	if err != nil {
		t.Fatalf("load v6 module: %v", err)
	}
	ctx := context.Background()
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)
	evaluator := NewPolicyEvaluator(pool, "h")

	if got := evaluator.FieldsRead(api.EventTypeProcess); got != mask {
		t.Fatalf("declared fields = %#x, want %#x", got, mask)
	}
	if !evaluator.RequiresCompleteCapture(api.EventTypeProcess) {
		t.Fatal("require-complete declaration lost")
	}
	if got, want := evaluator.RequiredCaptureFields(api.EventTypeProcess), uint32(compiler.FieldBitPath|compiler.FieldBitPPID); got != want {
		t.Fatalf("required capture fields = %#x, want %#x", got, want)
	}
	metadata := evaluator.Metadata()
	if err := metadata.Validate(metadata.ModuleSHA256); err != nil {
		t.Fatalf("v6 metadata rejected: %v", err)
	}
	if metadata.ABIVersion != CaptureQualityABIVersion || metadata.Events[0].FieldsRead != mask {
		t.Fatalf("metadata round trip diverged: %+v", metadata)
	}
}

func TestABIV6_BackwardCompatibility(t *testing.T) {
	// ABI 4/5 modules keep their exact behavior: they load, evaluate, and do
	// not receive the v6 carriage. The new version is accepted alongside them.
	for _, v := range []uint32{4, 5, 6} {
		t.Run(string(rune('0'+v)), func(t *testing.T) {
			rt, err := loadTestModule(t, fnMalloc, fnFree, fnJSONAllow, abiVersion(int32(v)))
			if err != nil {
				t.Fatalf("load ABI %d: %v", v, err)
			}
			if got := evalOnce(t, rt); got != api.ActionAllow {
				t.Fatalf("ABI %d action = %v, want ALLOW", v, got)
			}
			ctx := context.Background()
			pool, err := NewPool(ctx, rt, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := pool.Metadata().ABIVersion; got != v {
				t.Fatalf("reported ABI = %d, want %d", got, v)
			}
			_ = pool.Close(ctx)
		})
	}
}
