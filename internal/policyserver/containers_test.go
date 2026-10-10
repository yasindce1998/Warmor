package policyserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestContainerBindAndDelete(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	body, _ := json.Marshal(ContainerBinding{ContainerID: "c1", PID: 100, PolicyID: "p1", Labels: map[string]string{"app": "web"}})
	resp, err := http.Post(ts.URL+"/api/v1/containers/bind", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bind: status %d", resp.StatusCode)
	}
	if out["status"] != "bound" || out["container_id"] != "c1" || out["policy_id"] != "p1" {
		t.Errorf("unexpected bind response: %v", out)
	}

	if pid, ok := srv.GetContainerPolicy("c1"); !ok || pid != "p1" {
		t.Errorf("expected c1 -> p1, got %q %v", pid, ok)
	}
	if _, ok := srv.GetContainerPolicy("unknown"); ok {
		t.Error("expected unknown container lookup to fail")
	}
	if list := srv.ListContainerBindings(); len(list) != 1 || list[0].PID != 100 {
		t.Errorf("unexpected bindings: %+v", list)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/containers/c1", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d", resp.StatusCode)
	}
	if _, ok := srv.GetContainerPolicy("c1"); ok {
		t.Error("expected binding removed")
	}
	if len(srv.ListContainerBindings()) != 0 {
		t.Error("expected no bindings after delete")
	}
}

func TestContainerEndpointErrors(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"bind wrong method", http.MethodGet, "/api/v1/containers/bind", "", http.StatusMethodNotAllowed},
		{"bind bad json", http.MethodPost, "/api/v1/containers/bind", "{", http.StatusBadRequest},
		{"bind missing container", http.MethodPost, "/api/v1/containers/bind", `{"policy_id":"p"}`, http.StatusBadRequest},
		{"bind missing policy", http.MethodPost, "/api/v1/containers/bind", `{"container_id":"c"}`, http.StatusBadRequest},
		{"delete wrong method", http.MethodGet, "/api/v1/containers/c1", "", http.StatusMethodNotAllowed},
		{"delete empty id", http.MethodDelete, "/api/v1/containers/", "", http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, ts.URL+tc.path, bytes.NewBufferString(tc.body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("expected %d, got %d", tc.want, resp.StatusCode)
			}
		})
	}
	if len(srv.ListContainerBindings()) != 0 {
		t.Error("invalid requests must not create bindings")
	}
}

// Bindings belong to a Server instance, not to the package.
func TestContainerBindingsArePerServer(t *testing.T) {
	a, tsA := setupTestServer(t)
	defer tsA.Close()
	b, tsB := setupTestServer(t)
	defer tsB.Close()

	body, _ := json.Marshal(ContainerBinding{ContainerID: "c1", PolicyID: "p1"})
	resp, err := http.Post(tsA.URL+"/api/v1/containers/bind", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, ok := a.GetContainerPolicy("c1"); !ok {
		t.Fatal("expected binding on server A")
	}
	if _, ok := b.GetContainerPolicy("c1"); ok {
		t.Error("binding on server A leaked into server B")
	}

	// Returned bindings are copies.
	list := a.ListContainerBindings()
	list[0].PolicyID = "mutated"
	if pid, _ := a.GetContainerPolicy("c1"); pid != "p1" {
		t.Errorf("ListContainerBindings must return copies, got %q", pid)
	}
}
