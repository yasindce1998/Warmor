// Package workload prepares verified workload identity and policy selection.
// It does not activate policy, establish cgroup provenance, or open sockets.
package workload

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// CRIClient is the inventory subset of the real CRI v1 gRPC client. The caller
// owns connection lifecycle, deadlines, credentials, limits, and authorization.
type CRIClient interface {
	ListContainers(context.Context, *runtimeapi.ListContainersRequest, ...grpc.CallOption) (*runtimeapi.ListContainersResponse, error)
	ListPodSandbox(context.Context, *runtimeapi.ListPodSandboxRequest, ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error)
}

var _ CRIClient = runtimeapi.RuntimeServiceClient(nil)

// Inventory contains real CRI objects. The two lists are not an atomic runtime
// snapshot; NewSnapshot accepts only independently corroborated running joins.
type Inventory struct {
	Containers []*runtimeapi.Container
	Sandboxes  []*runtimeapi.PodSandbox
}

// FetchInventory calls real CRI v1 methods using the caller's bounded context.
// Any failure returns no inventory, not an authoritative empty snapshot.
// Polling/reconnect scheduling and freshness are the caller's responsibility.
func FetchInventory(ctx context.Context, client CRIClient) (Inventory, error) {
	if client == nil {
		return Inventory{}, fmt.Errorf("CRI inventory: nil client")
	}
	sandboxes, err := client.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{})
	if err != nil {
		return Inventory{}, fmt.Errorf("CRI ListPodSandbox: %w", err)
	}
	if sandboxes == nil {
		return Inventory{}, fmt.Errorf("CRI ListPodSandbox: nil response")
	}
	containers, err := client.ListContainers(ctx, &runtimeapi.ListContainersRequest{})
	if err != nil {
		return Inventory{}, fmt.Errorf("CRI ListContainers: %w", err)
	}
	if containers == nil {
		return Inventory{}, fmt.Errorf("CRI ListContainers: nil response")
	}
	return Inventory{Containers: containers.Containers, Sandboxes: sandboxes.Items}, nil
}
