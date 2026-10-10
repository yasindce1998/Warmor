package container

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"time"
)

type ContainerdTask struct {
	ID        string `json:"id"`
	PID       uint32 `json:"pid"`
	Status    string `json:"status"`
	Namespace string `json:"namespace"`
}

type ShimPlugin struct {
	socketPath string
	client     *http.Client
	scope      *PolicyScope
	logger     *slog.Logger
}

func NewShimPlugin(socketPath string, scope *PolicyScope, logger *slog.Logger) *ShimPlugin {
	if socketPath == "" {
		socketPath = "/run/containerd/containerd.sock"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 5*time.Second)
		},
	}
	return &ShimPlugin{
		socketPath: socketPath,
		client:     &http.Client{Transport: transport, Timeout: 10 * time.Second},
		scope:      scope,
		logger:     logger,
	}
}

func (s *ShimPlugin) ListTasks(ctx context.Context, namespace string) ([]ContainerdTask, error) {
	url := "http://localhost/containerd.services.tasks.v1.Tasks/List?namespace=" + neturl.QueryEscape(namespace)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list tasks: unexpected status %s", resp.Status)
	}

	var result struct {
		Tasks []ContainerdTask `json:"tasks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Tasks, nil
}

func (s *ShimPlugin) SyncRunningContainers(ctx context.Context) error {
	for _, ns := range []string{"k8s.io", "default"} {
		tasks, err := s.ListTasks(ctx, ns)
		if err != nil {
			s.logger.Warn("failed to list tasks", "namespace", ns, "err", err)
			continue
		}
		for _, t := range tasks {
			if t.Status == "RUNNING" {
				info := &ContainerInfo{
					ID:        t.ID,
					PID:       int(t.PID),
					Namespace: ns,
					Runtime:   RuntimeContainerd,
				}
				labels, err := ReadContainerLabels(t.ID)
				if err == nil {
					info.Labels = labels
					if img, ok := labels["io.kubernetes.container.image"]; ok {
						info.Image = img
					}
				}
				if policyID, ok := labels["io.warmor/policy"]; ok {
					s.scope.BindWithInfo(info, policyID)
					s.logger.Info("synced container policy", "container", t.ID, "policy", policyID)
				}
			}
		}
	}
	return nil
}
