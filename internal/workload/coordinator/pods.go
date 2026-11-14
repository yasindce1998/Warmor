package coordinator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

type PodHTTPConfig struct {
	BaseURL, NodeName string
	// Client must authenticate the API server using a trusted CA. Redirects are
	// disabled on a private copy to prevent bearer-token disclosure. The caller
	// owns the transport and its idle connections. Token is reloaded per request.
	Client                                                                        *http.Client
	Token                                                                         func() (string, error)
	RequestTimeout, WatchDuration                                                 time.Duration
	MaxPods, PageSize, MaxListBytes, MaxEventBytes, MaxWatchEvents, MaxWatchBytes int
}

func DefaultPodHTTPConfig(baseURL, node string, client *http.Client) PodHTTPConfig {
	return PodHTTPConfig{BaseURL: baseURL, NodeName: node, Client: client,
		RequestTimeout: 10 * time.Second, WatchDuration: 20 * time.Second,
		MaxPods: 2048, PageSize: 500, MaxListBytes: 16 << 20, MaxEventBytes: 1 << 20, MaxWatchEvents: 8192, MaxWatchBytes: 32 << 20}
}

type PodHTTPSource struct {
	cfg    PodHTTPConfig
	client http.Client
	base   string
}

func NewPodHTTPSource(cfg PodHTTPConfig) (*PodHTTPSource, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("Pod source requires an explicit HTTPS API server root")
	}
	if cfg.Client == nil || len(validation.IsDNS1123Subdomain(cfg.NodeName)) != 0 ||
		cfg.RequestTimeout < time.Millisecond || cfg.RequestTimeout > time.Minute ||
		cfg.WatchDuration < time.Second || cfg.WatchDuration > 5*time.Minute ||
		cfg.MaxPods < 1 || cfg.MaxPods > 65536 || cfg.PageSize < 1 || cfg.PageSize > 1000 ||
		cfg.MaxListBytes < 1024 || cfg.MaxListBytes > 64<<20 || cfg.MaxEventBytes < 1024 || cfg.MaxEventBytes > 4<<20 ||
		cfg.MaxWatchEvents < 1 || cfg.MaxWatchEvents > 65536 || cfg.MaxWatchBytes < 1024 || cfg.MaxWatchBytes > 64<<20 {
		return nil, errors.New("invalid Pod source bounds or node")
	}
	client := *cfg.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &PodHTTPSource{cfg: cfg, client: client, base: strings.TrimSuffix(cfg.BaseURL, "/")}, nil
}

// Sync lists all pages at a consistent resourceVersion, then watches the same
// node filter from that opaque version. Every return causes the coordinator to
// revoke the cache. 410, malformed events, budgets, auth errors, and disconnects
// therefore require a new list, never an unversioned watch continuation.
func (s *PodHTTPSource) Sync(ctx context.Context, publish func([]corev1.Pod) error) error {
	pods, rv, err := s.list(ctx)
	if err != nil {
		return err
	}
	sizes := make(map[types.NamespacedName]int, len(pods))
	cacheBytes := 0
	for key, p := range pods {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		sizes[key] = len(data)
		cacheBytes += len(data)
	}
	if cacheBytes > s.cfg.MaxListBytes {
		return errors.New("Pod cache byte budget exceeded")
	}
	if err := publish(podValues(pods)); err != nil {
		return err
	}
	watchCtx, cancel := context.WithTimeout(ctx, s.cfg.WatchDuration)
	defer cancel()
	q := s.query()
	q.Set("watch", "true")
	q.Set("allowWatchBookmarks", "true")
	q.Set("resourceVersion", rv)
	q.Set("timeoutSeconds", strconv.Itoa(max(1, int(s.cfg.WatchDuration/time.Second))))
	resp, err := s.get(watchCtx, q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reader := bufio.NewReaderSize(resp.Body, 4096)
	watchBytes := 0
	for n := 0; n < s.cfg.MaxWatchEvents; n++ {
		frame, err := boundedLine(reader, s.cfg.MaxEventBytes)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) || (watchCtx.Err() != nil && ctx.Err() == nil) {
				return nil
			}
			return err
		}
		watchBytes += len(frame)
		if watchBytes > s.cfg.MaxWatchBytes {
			return errors.New("Pod watch total byte budget exceeded")
		}
		var event struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(frame, &event); err != nil {
			return fmt.Errorf("invalid Pod watch frame: %w", err)
		}
		if event.Type == "ERROR" {
			return errors.New("Pod watch API error; relist required")
		}
		var p corev1.Pod
		if err := json.Unmarshal(event.Object, &p); err != nil {
			return fmt.Errorf("invalid watched Pod: %w", err)
		}
		if p.ResourceVersion == "" || len(p.ResourceVersion) > 4096 {
			return errors.New("missing or oversized watch resourceVersion")
		}
		if event.Type == "BOOKMARK" {
			continue
		} // Not a whole-cache freshness renewal.
		if err := s.validPod(&p); err != nil {
			return err
		}
		key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
		old, exists := pods[key]
		switch event.Type {
		case "ADDED":
			// Same name, new UID: replacement retires the previous UID in the
			// same atomic publication. No old/new overlap is permitted.
			pods[key] = p
			cacheBytes += len(event.Object) - sizes[key]
			sizes[key] = len(event.Object)
		case "MODIFIED":
			if !exists || old.UID != p.UID {
				return errors.New("Pod modification UID conflict; relist required")
			}
			pods[key] = p
			cacheBytes += len(event.Object) - sizes[key]
			sizes[key] = len(event.Object)
		case "DELETED":
			// A delayed delete for a former UID must not remove its successor.
			if exists && old.UID == p.UID {
				delete(pods, key)
				cacheBytes -= sizes[key]
				delete(sizes, key)
			}
		default:
			return errors.New("unsupported Pod watch event")
		}
		if len(pods) > s.cfg.MaxPods {
			return errors.New("Pod watch object budget exceeded")
		}
		if cacheBytes > s.cfg.MaxListBytes {
			return errors.New("Pod cache byte budget exceeded")
		}
		if err := publish(podValues(pods)); err != nil {
			return err
		}
	}
	return nil // bounded resync, not unlimited streaming work
}

func (s *PodHTTPSource) query() url.Values {
	return url.Values{"fieldSelector": {fields.OneTermEqualSelector("spec.nodeName", s.cfg.NodeName).String()}}
}

func (s *PodHTTPSource) get(ctx context.Context, q url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/api/v1/pods?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if s.cfg.Token != nil {
		token, err := s.cfg.Token()
		if err != nil {
			return nil, errors.New("read Pod API credentials")
		}
		if token == "" || len(token) > 1<<20 {
			return nil, errors.New("invalid Pod API credentials")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("Pod API HTTP %d; relist required", resp.StatusCode)
	}
	return resp, nil
}

func (s *PodHTTPSource) list(ctx context.Context) (map[types.NamespacedName]corev1.Pod, string, error) {
	pods := make(map[types.NamespacedName]corev1.Pod)
	uids := make(map[types.UID]bool)
	q := s.query()
	q.Set("limit", strconv.Itoa(s.cfg.PageSize))
	rv, continuation := "", ""
	// The byte budget applies across all pages. Empty looping pages cannot
	// bypass it or the explicit page-count bound.
	budget := s.cfg.MaxListBytes
	for page := 0; page <= s.cfg.MaxPods; page++ {
		q.Set("continue", continuation)
		requestCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		resp, err := s.get(requestCtx, q)
		if err != nil {
			cancel()
			return nil, "", err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, int64(budget)+1))
		resp.Body.Close()
		cancel()
		if err != nil {
			return nil, "", err
		}
		budget -= len(data)
		if budget < 0 {
			return nil, "", errors.New("Pod list byte budget exceeded")
		}
		var list corev1.PodList
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, "", err
		}
		if list.ResourceVersion == "" || len(list.ResourceVersion) > 4096 || (rv != "" && list.ResourceVersion != rv) {
			return nil, "", errors.New("inconsistent Pod list resourceVersion")
		}
		rv = list.ResourceVersion
		for _, p := range list.Items {
			if err := s.validPod(&p); err != nil {
				return nil, "", err
			}
			key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
			if _, ok := pods[key]; ok || uids[p.UID] {
				return nil, "", errors.New("duplicate Pod list identity")
			}
			pods[key], uids[p.UID] = p, true
			if len(pods) > s.cfg.MaxPods {
				return nil, "", errors.New("Pod list object budget exceeded")
			}
		}
		if list.Continue == "" {
			return pods, rv, nil
		}
		if len(list.Continue) > 4096 || continuation == list.Continue {
			return nil, "", errors.New("invalid Pod list continuation")
		}
		continuation = list.Continue
	}
	return nil, "", errors.New("Pod list page budget exceeded")
}

func (s *PodHTTPSource) validPod(p *corev1.Pod) error {
	if p.UID == "" || len(p.UID) > 256 || p.Name == "" || p.Namespace == "" || p.Spec.NodeName != s.cfg.NodeName {
		return errors.New("incomplete or nonlocal Pod identity")
	}
	return nil
}

func podValues(pods map[types.NamespacedName]corev1.Pod) []corev1.Pod {
	out := make([]corev1.Pod, 0, len(pods))
	for _, p := range pods {
		if p.DeletionTimestamp == nil {
			out = append(out, *p.DeepCopy())
		}
	}
	return out
}

func boundedLine(r *bufio.Reader, limit int) ([]byte, error) {
	var frame []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(frame)+len(part) > limit {
			return nil, errors.New("Pod watch frame byte budget exceeded")
		}
		frame = append(frame, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(bytes.TrimSpace(frame)) > 0 {
			return frame, nil
		}
		return frame, err
	}
}
