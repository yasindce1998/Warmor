package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Runtime string

const (
	RuntimeContainerd Runtime = "containerd"
	RuntimeCRIO       Runtime = "cri-o"
	RuntimeDocker     Runtime = "docker"
	RuntimeUnknown    Runtime = "unknown"
)

type ContainerInfo struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Labels    map[string]string `json:"labels"`
	PID       int               `json:"pid"`
	CgroupID  uint64            `json:"cgroup_id"`
	Namespace string            `json:"namespace"`
	Runtime   Runtime           `json:"runtime"`
}

// hostRoot is the filesystem root under which runtime sockets and task
// state are looked up. It is a variable so tests can point it at a fake tree.
var hostRoot = "/"

func DetectRuntime() Runtime {
	if _, err := os.Stat(filepath.Join(hostRoot, "run/containerd/containerd.sock")); err == nil {
		return RuntimeContainerd
	}
	if _, err := os.Stat(filepath.Join(hostRoot, "var/run/crio/crio.sock")); err == nil {
		return RuntimeCRIO
	}
	if _, err := os.Stat(filepath.Join(hostRoot, "var/run/docker.sock")); err == nil {
		return RuntimeDocker
	}
	return RuntimeUnknown
}

func ContainerFromCgroup(cgroupPath string) (*ContainerInfo, error) {
	parts := strings.Split(cgroupPath, "/")
	if len(parts) < 3 {
		return nil, fmt.Errorf("cgroup path too short: %s", cgroupPath)
	}

	info := &ContainerInfo{
		Labels: make(map[string]string),
	}

	for _, part := range parts {
		if id, ok := strings.CutPrefix(part, "cri-containerd-"); ok {
			info.ID = strings.TrimSuffix(id, ".scope")
			info.Runtime = RuntimeContainerd
			break
		}
		if id, ok := strings.CutPrefix(part, "crio-"); ok {
			info.ID = strings.TrimSuffix(id, ".scope")
			info.Runtime = RuntimeCRIO
			break
		}
		if id, ok := strings.CutPrefix(part, "docker-"); ok {
			info.ID = strings.TrimSuffix(id, ".scope")
			info.Runtime = RuntimeDocker
			break
		}
		if len(part) == 64 && !strings.Contains(part, "-") {
			info.ID = part
			info.Runtime = DetectRuntime()
			break
		}
	}

	if info.ID == "" {
		return nil, fmt.Errorf("no container ID found in cgroup path: %s", cgroupPath)
	}

	return info, nil
}

func ReadContainerLabels(containerID string) (map[string]string, error) {
	paths := []string{
		filepath.Join(hostRoot, "run/containerd/io.containerd.runtime.v2.task/k8s.io", containerID, "config.json"),
		filepath.Join(hostRoot, "run/containerd/io.containerd.runtime.v2.task/default", containerID, "config.json"),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(data, &spec); err == nil && spec.Annotations != nil {
			return spec.Annotations, nil
		}
	}

	return nil, fmt.Errorf("labels not found for container %s", containerID)
}
