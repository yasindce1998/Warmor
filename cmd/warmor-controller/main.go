// warmor-controller watches WarmorPolicy custom resources and keeps the
// effective node policy in sync: it validates and compiles the policies
// into a single WASM module, publishes it in a ConfigMap the agent
// DaemonSet mounts, and reports per-CR status. See
// docs/design/warmorpolicy-controller.md.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/controller"
	"github.com/yasindce1998/warmor/internal/kube"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	kubeconfig        = flag.String("kubeconfig", "", "Kubeconfig path (defaults to the in-cluster service account config; also try $KUBECONFIG or ~/.kube/config)")
	namespace         = flag.String("namespace", "", "Namespace whose WarmorPolicies are watched (empty: the namespace this pod runs in; \"*\": all namespaces — see --all-namespaces)")
	allNamespaces     = flag.Bool("all-namespaces", false, "Watch WarmorPolicies in every namespace and merge them into one node-wide policy (single-tenant clusters only: any namespace can then affect every node)")
	configMapName     = flag.String("configmap-name", "warmor-effective-policy", "Name of the ConfigMap the compiled effective policy is published to")
	configMapNS       = flag.String("configmap-namespace", "", "Namespace of the policy ConfigMap (default: the namespace this pod runs in)")
	policyName        = flag.String("policy-name", "warmor-effective", "Name recorded in the compiled effective policy")
	defaultPolicyPath = flag.String("default-policy", "/etc/warmor-controller/default-policy.wasm", "Compiled policy synced while no WarmorPolicy exists (the cluster's baked default)")
	cacheDir          = flag.String("cache-dir", "/var/lib/warmor-controller/cache", "Directory caching compiled policies across restarts (empty: no cache)")
	resyncPeriod      = flag.Duration("resync-period", 10*time.Minute, "Re-reconcile this often even without events, healing out-of-band edits to the policy ConfigMap (0 disables)")
	compileTimeout    = flag.Duration("compile-timeout", 2*time.Minute, "Maximum time allowed for one policy compilation (must be positive)")
	metricsAddress    = flag.String("metrics-address", ":9091", "Controller metrics/probes listener; readiness means recent local reconciliation, not node application")
	showVersion       = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()
	if *showVersion {
		log.Printf("warmor-controller %s", version.Version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if *compileTimeout <= 0 {
		log.Fatal("--compile-timeout must be positive")
	}
	defer stop()

	cfg := loadConfig()

	// Resolve namespace defaults before overriding with the all flag.
	podNamespace := kube.PodNamespace()
	targetNamespace := podNamespace
	switch {
	case *allNamespaces:
		targetNamespace = ""
		log.Printf("⚠️  Watching WarmorPolicies in ALL namespaces: every namespace can affect every node. Only use this on single-tenant clusters.")
	case *namespace == "*":
		log.Fatalf("--namespace \"*\" is not valid; use --all-namespaces")
	case *namespace != "":
		targetNamespace = *namespace
	}
	cmNamespace := *configMapNS
	if cmNamespace == "" {
		cmNamespace = podNamespace
	}

	opts := controller.Options{
		Namespace:          targetNamespace,
		ConfigMapNamespace: cmNamespace,
		ConfigMapName:      *configMapName,
		PolicyName:         *policyName,
		DefaultPolicyPath:  *defaultPolicyPath,
		CacheDir:           *cacheDir,
		ResyncPeriod:       *resyncPeriod,
		CompileTimeout:     *compileTimeout,
	}
	ctl := controller.New(kube.New(cfg), opts)
	listener, err := net.Listen("tcp", *metricsAddress)
	if err != nil {
		log.Fatalf("controller probes: %v", err)
	}
	server := &http.Server{
		Handler: ctl.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute,
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("controller probes failed: %v", err)
			stop()
		}
	}()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("controller probes shutdown: %v", err)
		}
	}()

	log.Printf("WarmorPolicy controller starting: watching %s, publishing %s/%s",
		namespaceLabel(targetNamespace), cmNamespace, *configMapName)
	if err := ctl.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("controller: %v", err)
	}
	log.Println("controller stopped")
}

// loadConfig finds API server credentials: an explicit --kubeconfig, the
// in-cluster service account when available, else a kubeconfig from the
// environment for running against a dev or kind cluster.
func loadConfig() *kube.Config {
	path := *kubeconfig
	if path == "" {
		if cfg, ok := kube.InClusterConfig(); ok {
			return cfg
		}
		path = os.Getenv("KUBECONFIG")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			candidate := home + "/.kube/config"
			if _, statErr := os.Stat(candidate); statErr == nil {
				path = candidate
			}
		}
	}
	if path == "" {
		log.Fatal("no Kubernetes configuration: not running in a cluster and no kubeconfig found (pass --kubeconfig)")
	}
	cfg, err := kube.LoadKubeconfig(path)
	if err != nil {
		log.Fatalf("load kubeconfig: %v", err)
	}
	log.Printf("Using kubeconfig %s (not running in a cluster)", path)
	return cfg
}

func namespaceLabel(ns string) string {
	if ns == "" {
		return "all namespaces"
	}
	return "namespace " + ns
}
