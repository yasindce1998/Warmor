package workload

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Actual CRI protobuf/gRPC on an in-memory listener: no runtime socket, host
// network, or Kubernetes cluster is used. This is protocol, not deployment proof.
type criServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	inventory                                    Inventory
	failSandboxes, failContainers, waitForCancel bool
	mu                                           sync.Mutex
	methods                                      []string
}

func (s *criServer) ListPodSandbox(ctx context.Context, req *runtimeapi.ListPodSandboxRequest) (*runtimeapi.ListPodSandboxResponse, error) {
	s.mu.Lock()
	s.methods = append(s.methods, "ListPodSandbox")
	s.mu.Unlock()
	if req.Filter != nil {
		return nil, status.Error(codes.InvalidArgument, "unexpected filter")
	}
	if s.waitForCancel {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.failSandboxes {
		return nil, status.Error(codes.Unavailable, "sandbox inventory unavailable")
	}
	return &runtimeapi.ListPodSandboxResponse{Items: s.inventory.Sandboxes}, nil
}

func (s *criServer) ListContainers(_ context.Context, req *runtimeapi.ListContainersRequest) (*runtimeapi.ListContainersResponse, error) {
	s.mu.Lock()
	s.methods = append(s.methods, "ListContainers")
	s.mu.Unlock()
	if req.Filter != nil {
		return nil, status.Error(codes.InvalidArgument, "unexpected filter")
	}
	if s.failContainers {
		return nil, status.Error(codes.PermissionDenied, "container inventory forbidden")
	}
	return &runtimeapi.ListContainersResponse{Containers: s.inventory.Containers}, nil
}

func realCRIClient(t *testing.T, service *criServer) runtimeapi.RuntimeServiceClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///cri-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("gRPC server: %v", err)
		}
	})
	return runtimeapi.NewRuntimeServiceClient(connection)
}

func TestFetchInventoryRealCRIWireAndIdentityJoin(t *testing.T) {
	in := fixture()
	service := &criServer{inventory: in.Inventory}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inventory, err := FetchInventory(ctx, realCRIClient(t, service))
	if err != nil {
		t.Fatal(err)
	}
	in.Inventory = inventory
	if id := verifiedIdentity(t, in); id.ContainerID() != fullID {
		t.Fatal(id.ContainerID())
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if !reflect.DeepEqual(service.methods, []string{"ListPodSandbox", "ListContainers"}) {
		t.Fatalf("methods: %v", service.methods)
	}
}

func TestRealCRIWireSameNamedPodsRemainNamespaceIsolated(t *testing.T) {
	a, b := fixture(), fixture()
	b.Pods[0].UID = "pod-uid-b"
	b.Pods[0].Namespace = "team-b"
	b.Pods[0].Labels["app"] = "worker"
	b.Pods[0].Status.ContainerStatuses[0].ContainerID = "containerd://different-full-container-id"
	b.Inventory.Containers[0].Id = "different-full-container-id"
	b.Inventory.Containers[0].PodSandboxId = "sandbox-id-b"
	b.Inventory.Containers[0].Labels["io.kubernetes.pod.uid"] = "pod-uid-b"
	b.Inventory.Sandboxes[0].Id = "sandbox-id-b"
	b.Inventory.Sandboxes[0].Metadata.Uid = "pod-uid-b"
	b.Inventory.Sandboxes[0].Metadata.Namespace = "team-b"
	b.Bindings[0] = Binding{CgroupID: 99, Lifetime: "boot-a:pod-b-incarnation", ContainerID: "different-full-container-id"}
	in := Inputs{
		NodeName: a.NodeName, Runtime: a.Runtime,
		Pods: append(a.Pods, b.Pods...), Bindings: append(a.Bindings, b.Bindings...),
		Inventory: Inventory{Containers: append(a.Inventory.Containers, b.Inventory.Containers...), Sandboxes: append(a.Inventory.Sandboxes, b.Inventory.Sandboxes...)},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inventory, err := FetchInventory(ctx, realCRIClient(t, &criServer{inventory: in.Inventory}))
	if err != nil {
		t.Fatal(err)
	}
	in.Inventory = inventory
	snapshot, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	ca, cb := candidate("team-a", "policy-a", 2), candidate("team-b", "policy-b", 3)
	catalog, err := NewCatalog([]Candidate{cb, ca})
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range []PolicyGeneration{ca.Policy, cb.Policy} {
		binding := in.Bindings[n]
		identity, reason := snapshot.Lookup(binding.CgroupID, binding.Lifetime)
		if reason != Verified {
			t.Fatal(reason)
		}
		if got := catalog.Select(identity); !reflect.DeepEqual(got, []PolicyGeneration{want}) {
			t.Fatalf("pod %d selected %+v, want %+v", n, got, want)
		}
	}
	// A stale old Pod status cannot make the new runtime container inherit A.
	in.Pods[0].Status.ContainerStatuses[0].ContainerID = b.Pods[0].Status.ContainerStatuses[0].ContainerID
	snapshot, err = NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range in.Bindings {
		identity, reason := snapshot.Lookup(binding.CgroupID, binding.Lifetime)
		if reason == Verified || len(catalog.Select(identity)) != 0 {
			t.Fatalf("conflicting claim selected %+v, %s", identity, reason)
		}
	}
}

func TestFetchInventoryRPCFailuresReturnNoPartialSnapshot(t *testing.T) {
	for _, test := range []struct {
		name               string
		sandbox, container bool
		code               codes.Code
	}{
		{"sandbox error", true, false, codes.Unavailable}, {"container error", false, true, codes.PermissionDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := realCRIClient(t, &criServer{inventory: fixture().Inventory, failSandboxes: test.sandbox, failContainers: test.container})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			inventory, err := FetchInventory(ctx, client)
			if status.Code(err) != test.code || inventory.Containers != nil || inventory.Sandboxes != nil {
				t.Fatalf("inventory = %+v, err = %v", inventory, err)
			}
		})
	}
}

func TestFetchInventoryCancellation(t *testing.T) {
	client := realCRIClient(t, &criServer{waitForCancel: true})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := FetchInventory(ctx, client); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("deadline = %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := FetchInventory(ctx, client); status.Code(err) != codes.Canceled {
		t.Fatalf("cancellation = %v", err)
	}
}

type nilResponseClient struct{ container bool }

func (c nilResponseClient) ListPodSandbox(context.Context, *runtimeapi.ListPodSandboxRequest, ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error) {
	if c.container {
		return &runtimeapi.ListPodSandboxResponse{}, nil
	}
	return nil, nil
}

func (nilResponseClient) ListContainers(context.Context, *runtimeapi.ListContainersRequest, ...grpc.CallOption) (*runtimeapi.ListContainersResponse, error) {
	return nil, nil
}

func TestFetchInventoryRejectsNil(t *testing.T) {
	for _, client := range []CRIClient{nil, nilResponseClient{}, nilResponseClient{container: true}} {
		if _, err := FetchInventory(context.Background(), client); err == nil {
			t.Fatal("accepted nil client/response")
		}
	}
}

func TestFetchInventoryEmptyRuntimeIsAuthoritativeEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inventory, err := FetchInventory(ctx, realCRIClient(t, &criServer{}))
	if err != nil || len(inventory.Containers) != 0 || len(inventory.Sandboxes) != 0 {
		t.Fatalf("empty inventory = %+v, %v", inventory, err)
	}
}
