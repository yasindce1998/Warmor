package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}
func watchEvent(t *testing.T, w http.ResponseWriter, kind string, p corev1.Pod) {
	t.Helper()
	writeJSON(t, w, map[string]any{"type": kind, "object": p})
}

func TestPodListWatchPaginationRecreationAndOpaqueVersions(t *testing.T) {
	pods, _, _ := inputs()
	p := pods[0]
	p.ResourceVersion = "object-1"
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		q := r.URL.Query()
		if r.URL.Path != "/api/v1/pods" || q.Get("fieldSelector") != "spec.nodeName=node" || r.Header.Get("Authorization") != "Bearer rotated" {
			t.Error("missing node filter or credentials")
		}
		if q.Get("watch") == "true" {
			if q.Get("resourceVersion") != "opaque/list-a" || q.Get("allowWatchBookmarks") != "true" {
				t.Error("watch not anchored to list")
			}
			bookmark := corev1.Pod{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "not-a-number"}}
			watchEvent(t, w, "BOOKMARK", bookmark)
			changed := *p.DeepCopy()
			changed.ResourceVersion = "z"
			changed.Labels["app"] = "b"
			watchEvent(t, w, "MODIFIED", changed)
			recreated := *changed.DeepCopy()
			recreated.UID = "new-uid"
			recreated.ResourceVersion = "a"
			watchEvent(t, w, "ADDED", recreated)
			// Old UID delete cannot remove the recreated name.
			watchEvent(t, w, "DELETED", changed)
			watchEvent(t, w, "DELETED", recreated)
			return
		}
		if q.Get("limit") != "1" {
			t.Error("missing pagination bound")
		}
		if q.Get("continue") == "" {
			writeJSON(t, w, corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "opaque/list-a", Continue: "page-two"}, Items: []corev1.Pod{p}})
		} else if q.Get("continue") == "page-two" {
			writeJSON(t, w, corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "opaque/list-a"}})
		} else {
			t.Error("bad continuation")
		}
	}))
	defer server.Close()
	cfg := DefaultPodHTTPConfig(server.URL, "node", server.Client())
	cfg.PageSize = 1
	cfg.Token = func() (string, error) { return "rotated", nil }
	s, err := NewPodHTTPSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var snapshots [][]corev1.Pod
	err = s.Sync(context.Background(), func(p []corev1.Pod) error { snapshots = append(snapshots, p); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 3 || len(snapshots) != 5 {
		t.Fatalf("requests %d snapshots %d", requests.Load(), len(snapshots))
	}
	if snapshots[0][0].Labels["app"] != "a" || snapshots[1][0].Labels["app"] != "b" || snapshots[2][0].UID != "new-uid" || snapshots[3][0].UID != "new-uid" || len(snapshots[4]) != 0 {
		t.Fatalf("bad snapshots: %+v", snapshots)
	}
}

func TestPodSourceRejectsUntrustedOrUnboundedState(t *testing.T) {
	pods, _, _ := inputs()
	p := pods[0]
	p.ResourceVersion = "v"
	tests := []struct {
		name     string
		list     any
		event    string
		status   int
		maxBytes int
	}{
		{name: "foreign node", list: func() corev1.PodList {
			q := *p.DeepCopy()
			q.Spec.NodeName = "other"
			return corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "v"}, Items: []corev1.Pod{q}}
		}()},
		{name: "duplicate", list: corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "v"}, Items: []corev1.Pod{p, p}}},
		{name: "no version", list: corev1.PodList{Items: []corev1.Pod{p}}},
		{name: "HTTP gone", status: 410},
		{name: "watch gone", event: `{"type":"ERROR","object":{"code":410}}`},
		{name: "bad event", event: `{"type":"SURPRISE","object":{"metadata":{"uid":"uid","name":"app","namespace":"team","resourceVersion":"v"},"spec":{"nodeName":"node"}}}`},
		{name: "bad json", event: `{"type":`},
		{name: "frame budget", event: strings.Repeat("x", 2048)},
		{name: "list budget", list: map[string]string{"padding": strings.Repeat("x", 2048)}, maxBytes: 1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				if r.URL.Query().Get("watch") == "true" {
					fmt.Fprintln(w, tt.event)
					return
				}
				list := tt.list
				if list == nil {
					list = corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "v"}, Items: []corev1.Pod{p}}
				}
				writeJSON(t, w, list)
			}))
			defer server.Close()
			cfg := DefaultPodHTTPConfig(server.URL, "node", server.Client())
			cfg.MaxEventBytes = 1024
			if tt.maxBytes > 0 {
				cfg.MaxListBytes = tt.maxBytes
			}
			s, err := NewPodHTTPSource(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Sync(context.Background(), func([]corev1.Pod) error { return nil }); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
}

func TestPodSourceWatchCancellationAndRedirect(t *testing.T) {
	var redirected atomic.Bool
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Store(true) }))
	defer sink.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			writeJSON(t, w, corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "v"}})
			return
		}
		w.WriteHeader(200)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	cfg := DefaultPodHTTPConfig(server.URL, "node", server.Client())
	s, err := NewPodHTTPSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Sync(ctx, func([]corev1.Pod) error { return nil }); err == nil {
		t.Fatal("cancellation not returned")
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 302) }))
	defer redirect.Close()
	cfg.BaseURL = redirect.URL
	cfg.Client = redirect.Client()
	cfg.Token = func() (string, error) { return "secret", nil }
	s, err = NewPodHTTPSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background(), func([]corev1.Pod) error { return nil }); err == nil {
		t.Fatal("redirect accepted")
	}
	if redirected.Load() {
		t.Fatal("credentials redirected")
	}
	cfg.BaseURL = "http://localhost"
	if _, err := NewPodHTTPSource(cfg); err == nil {
		t.Fatal("plaintext API accepted")
	}
}

func TestPodSourceInconsistentPagesAndWatchUIDConflict(t *testing.T) {
	pods, _, _ := inputs()
	p := pods[0]
	p.ResourceVersion = "v"
	for _, mode := range []string{"pages", "uid"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("watch") == "true" {
					p := *p.DeepCopy()
					p.UID = "other"
					watchEvent(t, w, "MODIFIED", p)
					return
				}
				list := corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "v"}, Items: []corev1.Pod{p}}
				if mode == "pages" {
					list.Continue = "next"
					if q.Get("continue") != "" {
						list.ResourceVersion = "different"
					}
				}
				writeJSON(t, w, list)
			}))
			defer server.Close()
			s, err := NewPodHTTPSource(DefaultPodHTTPConfig(server.URL, "node", server.Client()))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Sync(context.Background(), func([]corev1.Pod) error { return nil }); err == nil {
				t.Fatal("inconsistent sequence accepted")
			}
		})
	}
}

func TestPodWatchTotalAndCacheByteBudgets(t *testing.T) {
	pods, _, _ := inputs()
	p := pods[0]
	p.ResourceVersion = "v"
	for _, mode := range []string{"total", "cache"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("watch") != "true" {
					writeJSON(t, w, corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "v"}, Items: []corev1.Pod{p}})
					return
				}
				for range 4 {
					changed := *p.DeepCopy()
					changed.Annotations = map[string]string{"padding": strings.Repeat("a", 800)}
					watchEvent(t, w, "MODIFIED", changed)
				}
			}))
			defer server.Close()
			cfg := DefaultPodHTTPConfig(server.URL, "node", server.Client())
			if mode == "total" {
				cfg.MaxWatchBytes = 1024
			} else {
				cfg.MaxListBytes = 1024
			}
			s, err := NewPodHTTPSource(cfg)
			if err != nil {
				t.Fatal(err)
			}
			publications := 0
			if err := s.Sync(context.Background(), func([]corev1.Pod) error { publications++; return nil }); err == nil {
				t.Fatal("unbounded watch/cache growth accepted")
			}
			if publications != 1 {
				t.Fatalf("oversized watch state published: %d", publications)
			}
		})
	}
}
