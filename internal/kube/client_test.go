package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(&Config{
		BaseURL: srv.URL,
		Token:   func() (string, error) { return "test-token", nil },
	})
}

func TestClient_RequestsCarryTokenAndDecodeResponses(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	var gotBody map[string]any
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		if r.Body != nil && r.ContentLength > 0 {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
		}
		fmt.Fprint(w, `{"metadata":{"resourceVersion":"42"},"items":[{"name":"p1"}]}`)
	}))

	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := client.Get(context.Background(), "/apis/warmor.io/v1alpha1/warmorpolicies", &list); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want the bearer token", gotAuth)
	}
	if list.Metadata.ResourceVersion != "42" || len(list.Items) != 1 || list.Items[0].Name != "p1" {
		t.Errorf("decoded list = %+v", list)
	}

	if err := client.Create(context.Background(), "/api/v1/namespaces/ns/configmaps",
		map[string]any{"metadata": map[string]any{"name": "cm"}}, nil); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/namespaces/ns/configmaps" {
		t.Errorf("create = %s %s", gotMethod, gotPath)
	}
	meta, ok := gotBody["metadata"].(map[string]any)
	if !ok || meta["name"] != "cm" {
		t.Errorf("create body = %v", gotBody)
	}
}

func TestClient_StatusErrors(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"kind":"Status","code":404,"reason":"NotFound","message":"no such thing"}`)
	}))

	err := client.Get(context.Background(), "/api/v1/namespaces/ns/configmaps/nope", &struct{}{})
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound(%v) = false, want true", err)
	}
	if !strings.Contains(err.Error(), "no such thing") {
		t.Errorf("error message = %q, want the API server's message", err)
	}
}

func TestClientRejectsCredentialBearingRedirects(t *testing.T) {
	called := false
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
	defer destination.Close()
	originServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer originServer.Close()
	pool := x509.NewCertPool()
	pool.AddCert(originServer.Certificate())
	origin := New(&Config{BaseURL: originServer.URL, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, Token: func() (string, error) { return "owned-controller-test", nil }})
	if err := origin.Create(context.Background(), "/apis/authentication.k8s.io/v1/tokenreviews", map[string]string{"token": "owned-test-only"}, nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if called {
		t.Fatal("redirect destination received token review")
	}
}

func TestClient_WatchStreamsEvents(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			t.Error("watch query missing")
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flushing")
			return
		}
		fmt.Fprint(w, `{"type":"ADDED","object":{"metadata":{"name":"a"}}}`+"\n")
		flusher.Flush()
		fmt.Fprint(w, `{"type":"DELETED","object":{"metadata":{"name":"a"}}}`+"\n")
	}))

	var types []string
	err := client.Watch(context.Background(), "/apis/warmor.io/v1alpha1/warmorpolicies?watch=true", func(ev WatchEvent) error {
		types = append(types, ev.Type)
		if len(types) == 2 {
			return fmt.Errorf("stop") // ends the watch from the callback side
		}
		return nil
	})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("watch returned %v, want the callback error", err)
	}
	if len(types) != 2 || types[0] != "ADDED" || types[1] != "DELETED" {
		t.Errorf("event types = %v", types)
	}
}

// TestClient_CancelUnblocksPendingRequest covers the pathology seen in the
// kind e2e: a request whose connection is established but whose response
// never arrives (blackholed pod network, half-open watch stream). Only
// context cancellation may end it — ResponseHeaderTimeout is far away and
// no bytes ever arrive.
func TestClient_CancelUnblocksPendingRequest(t *testing.T) {
	// A TCP listener that never accept()s: the kernel completes the
	// handshake from the backlog, so the dial "succeeds", but the server
	// never reads or writes — the connection is a black hole.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client := New(&Config{BaseURL: "http://" + ln.Addr().String()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		var out map[string]any
		done <- client.Get(ctx, "/apis/warmor.io/v1alpha1/warmorpolicies", &out)
	}()

	select {
	case err := <-done:
		t.Fatalf("request returned before cancel: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("request after cancel = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled request did not return within 5s — a pending request is not abortable")
	}
}

func TestClient_WatchEndsOnContextCancel(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"type":"ADDED","object":{}}`+"\n")
		<-block // hold the stream open; only ctx cancellation can end it
	}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.Watch(ctx, "/x?watch=true", func(WatchEvent) error { return nil })
	}()
	cancel()
	if err := <-done; err != context.Canceled {
		t.Errorf("watch after cancel = %v, want context.Canceled", err)
	}
}
