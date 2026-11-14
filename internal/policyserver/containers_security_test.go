package policyserver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeBindingsUseAuthenticatedOwner(t *testing.T) {
	for _, certAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "JWT", true: "mTLS"}[certAuth], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			store := openTestStore(t, path, StoreOptions{})
			s := NewServer(ServerConfig{JWTSecret: []byte("test-secret"), Store: store})
			request := func(subject, role, method, url, body string) int {
				t.Helper()
				r := httptest.NewRequest(method, url, bytes.NewBufferString(body))
				if certAuth && role != RoleAdmin {
					r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: subject}}}}}
				} else {
					token, err := s.jwt.Issue(subject, role, time.Hour)
					if err != nil {
						t.Fatal(err)
					}
					r.Header.Set("Authorization", "Bearer "+token)
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				return w.Code
			}
			const bind = "/api/v1/containers/bind"
			if got := request("runtime-a", RoleRuntime, http.MethodPost, bind, `{"container_id":"c","policy_id":"p","owner":"runtime-b","labels":{"app":"web"}}`); got != http.StatusOK {
				t.Fatalf("bind: %d", got)
			}
			bindings := s.ListContainerBindings()
			if len(bindings) != 1 || bindings[0].Owner != "runtime-a" {
				t.Fatal("client spoofed owner")
			}
			bindings[0].Labels["app"] = "attacker"
			if s.ListContainerBindings()[0].Labels["app"] != "web" {
				t.Fatal("labels not copied")
			}
			if got := request("runtime-b", RoleRuntime, http.MethodPost, bind, `{"container_id":"c","policy_id":"evil","owner":"runtime-a"}`); got != http.StatusForbidden {
				t.Fatalf("cross-runtime overwrite: %d", got)
			}
			if got := request("runtime-b", RoleRuntime, http.MethodDelete, "/api/v1/containers/c", ""); got != http.StatusForbidden {
				t.Fatalf("cross-runtime delete: %d", got)
			}
			if policy, _ := s.GetContainerPolicy("c"); policy != "p" {
				t.Fatal("denied overwrite changed policy")
			}
			if got := request("runtime-a", RoleRuntime, http.MethodPost, bind, `{"container_id":"c","policy_id":"p2","owner":"runtime-b"}`); got != http.StatusOK {
				t.Fatalf("owner update: %d", got)
			}
			if got := request("administrator", RoleAdmin, http.MethodPost, bind, `{"container_id":"c","policy_id":"p3","owner":"runtime-b"}`); got != http.StatusOK {
				t.Fatalf("admin update: %d", got)
			}
			if s.ListContainerBindings()[0].Owner != "runtime-a" {
				t.Fatal("admin update transferred ownership")
			}
			store.Close()
			store = openTestStore(t, path, StoreOptions{})
			s = NewServer(ServerConfig{JWTSecret: []byte("test-secret"), Store: store})
			if got := request("runtime-b", RoleRuntime, http.MethodDelete, "/api/v1/containers/c", ""); got != http.StatusForbidden {
				t.Fatalf("restart lost owner: %d", got)
			}
			if got := request("runtime-a", RoleRuntime, http.MethodDelete, "/api/v1/containers/c", ""); got != http.StatusNoContent {
				t.Fatalf("owner delete: %d", got)
			}
			if len(s.ListContainerBindings()) != 0 {
				t.Fatal("binding not removed")
			}
		})
	}
}

func TestRuntimeBindingLimitsAndFailedPersistence(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, filepath.Join(dir, "state.json"), StoreOptions{Limits: StoreLimits{MaxBindings: 1}})
	s := NewServer(ServerConfig{Insecure: true, Store: store})
	post := func(b ContainerBinding) int {
		data, _ := json.Marshal(b)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/containers/bind", bytes.NewReader(data))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if got := post(ContainerBinding{ContainerID: "a", PolicyID: "p"}); got != http.StatusOK {
		t.Fatalf("bind: %d", got)
	}
	if got := post(ContainerBinding{ContainerID: "b", PolicyID: "p"}); got != http.StatusConflict {
		t.Fatalf("limit: %d", got)
	}
	if len(s.ListContainerBindings()) != 1 {
		t.Fatal("binding limit not enforced")
	}
	store.backend.path = filepath.Join(dir, "missing", "state.json")
	if got := post(ContainerBinding{ContainerID: "a", PolicyID: "changed"}); got != http.StatusInternalServerError {
		t.Fatalf("disk failure: %d", got)
	}
	if got, _ := s.GetContainerPolicy("a"); got != "p" {
		t.Fatal("failed persistence changed binding")
	}
}
