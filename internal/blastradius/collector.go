package blastradius

import (
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// Collector populates the blast radius graph from streaming events.
type Collector struct {
	graph *Graph
}

// NewCollector creates a collector that feeds events into the given graph.
func NewCollector(graph *Graph) *Collector {
	return &Collector{graph: graph}
}

// ProcessEvent handles a security event, updating the graph with new relationships.
func (c *Collector) ProcessEvent(event *streaming.SecurityEvent) {
	if event == nil || event.CgroupID == 0 {
		return
	}

	now := event.Timestamp
	if now.IsZero() {
		now = c.graph.config.Clock()
	}

	c.ensureNode(event.CgroupID, event.Comm, now)

	switch event.EventType {
	case "network":
		c.handleNetworkEvent(event, now)
	case "mount":
		c.handleMountEvent(event, now)
	}
}

// RegisterSharedNamespace records a shared namespace relationship between containers.
func (c *Collector) RegisterSharedNamespace(cgroupA, cgroupB uint64, nsType EdgeType, timestamp time.Time) {
	c.graph.AddEdge(cgroupA, cgroupB, nsType, string(nsType), timestamp)
	c.graph.AddEdge(cgroupB, cgroupA, nsType, string(nsType), timestamp)
}

func (c *Collector) ensureNode(cgroupID uint64, comm string, now time.Time) {
	c.graph.AddNode(&ContainerNode{
		CgroupID:  cgroupID,
		Name:      comm,
		FirstSeen: now,
		LastSeen:  now,
	})
}

func (c *Collector) handleNetworkEvent(event *streaming.SecurityEvent, now time.Time) {
	if event.RemoteAddr == "" {
		return
	}

	details := event.RemoteAddr
	if event.RemotePort > 0 {
		details += ":" + portStr(event.RemotePort)
	}

	targetCgroup := c.resolveRemoteContainer(event.RemoteAddr, event.RemotePort)
	if targetCgroup == 0 {
		return
	}

	c.graph.AddEdge(event.CgroupID, targetCgroup, EdgeNetwork, details, now)
}

func (c *Collector) handleMountEvent(event *streaming.SecurityEvent, now time.Time) {
	if event.Filename == "" {
		return
	}

	targetCgroup := c.resolveVolumeContainer(event.Filename)
	if targetCgroup == 0 {
		return
	}

	c.graph.AddEdge(event.CgroupID, targetCgroup, EdgeSharedVolume, event.Filename, now)
}

func (c *Collector) resolveRemoteContainer(_ string, _ uint16) uint64 {
	return 0
}

func (c *Collector) resolveVolumeContainer(_ string) uint64 {
	return 0
}

func portStr(port uint16) string {
	buf := make([]byte, 0, 5)
	if port == 0 {
		return "0"
	}
	for port > 0 {
		buf = append(buf, byte('0'+port%10))
		port /= 10
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
