package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/pkg/controlplane"
)

type ociState struct {
	OciVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	PID         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations"`
}

func main() {
	action := flag.String("action", "start", "Hook action (start/stop)")
	serverURL := flag.String("server", "http://localhost:8443", "Warmor server URL")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var state ociState
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		logger.Error("failed to decode OCI state", "err", err)
		os.Exit(0)
	}

	switch *action {
	case "start":
		handleStart(state, *serverURL, logger)
	case "stop":
		handleStop(state, *serverURL, logger)
	}
}

func handleStart(state ociState, serverURL string, logger *slog.Logger) {
	policyID := ""

	if id, ok := state.Annotations["io.warmor/policy"]; ok {
		policyID = id
	} else if image, ok := state.Annotations["io.kubernetes.container.image"]; ok {
		policyID = inferPolicy(image)
	}

	if policyID == "" {
		return
	}

	payload := map[string]any{
		"container_id": state.ID,
		"pid":          state.PID,
		"policy_id":    policyID,
		"labels":       state.Annotations,
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(
		serverURL+controlplane.RouteContainersBind,
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		logger.Warn("failed to bind container policy", "err", err, "container", state.ID)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warn("bind returned non-200", "status", resp.StatusCode, "container", state.ID)
	} else {
		logger.Info("container bound to policy", "container", state.ID, "policy", policyID)
	}
}

func handleStop(state ociState, serverURL string, logger *slog.Logger) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("DELETE",
		fmt.Sprintf("%s/api/v1/containers/%s", serverURL, state.ID), nil)
	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("failed to unbind container", "err", err, "container", state.ID)
		return
	}
	defer resp.Body.Close()
	logger.Info("container unbound", "container", state.ID)
}

func inferPolicy(image string) string {
	parts := strings.Split(image, "/")
	name := parts[len(parts)-1]
	if idx := strings.Index(name, ":"); idx > 0 {
		name = name[:idx]
	}
	return name + "-default"
}
