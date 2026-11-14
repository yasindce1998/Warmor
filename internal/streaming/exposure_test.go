package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestGeneralExportsRequireSensitiveInputOptIn(t *testing.T) {
	event := FromAPIEvent(&api.Event{Comm: "app", Process: &api.ProcessEvent{Args: []string{"app", "--password", "secret-token"}}}, nil)
	for _, full := range []bool{false, true} {
		var output bytes.Buffer
		sink := NewStdoutSink()
		sink.IncludePolicyInput, sink.enc = full, json.NewEncoder(&output)
		if err := sink.Write(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "secret-token") != full {
			t.Fatalf("stdout opt-in=%t: %s", full, output.String())
		}
		var payload string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { data, _ := io.ReadAll(r.Body); payload = string(data) }))
		webhook := NewWebhookSink(WebhookConfig{URL: server.URL, BatchSize: 1, IncludePolicyInput: full})
		if err := webhook.Write(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		if err := webhook.Close(); err != nil {
			t.Fatal(err)
		}
		server.Close()
		if strings.Contains(payload, "secret-token") != full {
			t.Fatalf("webhook opt-in=%t: %s", full, payload)
		}
		if !full && (!strings.Contains(payload, "redacted") || !strings.Contains(output.String(), "redacted")) {
			t.Fatal("export failed to mark incomplete evidence")
		}
	}
	if event.PolicyInput == nil || event.PolicyInput.Process.Args[2] != "secret-token" {
		t.Fatal("export modified authoritative recording")
	}
}
