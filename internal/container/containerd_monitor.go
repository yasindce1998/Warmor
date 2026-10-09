package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type ContainerdEvent struct {
	Topic     string `json:"topic"`
	Container string `json:"container_id"`
	Namespace string `json:"namespace"`
	Image     string `json:"image"`
	PID       int    `json:"pid"`
}

type EventHandler func(event ContainerdEvent)

type ContainerdMonitor struct {
	socketPath string
	client     *http.Client
	handler    EventHandler
	logger     *slog.Logger
}

func NewContainerdMonitor(socketPath string, handler EventHandler, logger *slog.Logger) *ContainerdMonitor {
	if socketPath == "" {
		socketPath = "/run/containerd/containerd.sock"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 5*time.Second)
		},
	}
	return &ContainerdMonitor{
		socketPath: socketPath,
		client:     &http.Client{Transport: transport},
		handler:    handler,
		logger:     logger,
	}
}

func (m *ContainerdMonitor) Watch(ctx context.Context) error {
	m.logger.Info("starting containerd event monitor", "socket", m.socketPath)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// poll returns nil when the stream ends cleanly; reconnect
		// immediately so no events are missed. Only real errors back off.
		if err := m.poll(ctx); err != nil {
			m.logger.Warn("containerd poll error", "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (m *ContainerdMonitor) poll(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/events", nil)
	if err != nil {
		return err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("containerd events request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("containerd events request: unexpected status %s", resp.Status)
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var event ContainerdEvent
		if err := dec.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		m.handler(event)
	}
}
