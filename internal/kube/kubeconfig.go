package kube

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadKubeconfig reads a kubeconfig file and returns the config for the
// current context (or the only context, when no current-context is set).
// Only the pieces the controller needs are understood: server URL, CA
// (file or inline), and one of token, basic username/password is NOT
// supported (use a token), client certificate/key (file or inline).
func LoadKubeconfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig: %w", err)
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}

	clusters := make(map[string]kubeCluster, len(kc.Clusters))
	for _, c := range kc.Clusters {
		clusters[c.Name] = c.Cluster
	}
	users := make(map[string]kubeUser, len(kc.Users))
	for _, u := range kc.Users {
		users[u.Name] = u.User
	}

	name := kc.CurrentContext
	if name == "" && len(kc.Contexts) == 1 {
		name = kc.Contexts[0].Name
	}
	var ctx kubeContext
	found := false
	for _, c := range kc.Contexts {
		if c.Name == name {
			ctx, found = c.Context, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("kubeconfig: context %q not found", name)
	}

	cluster, ok := clusters[ctx.Cluster]
	if !ok {
		return nil, fmt.Errorf("kubeconfig: cluster %q not found", ctx.Cluster)
	}
	if cluster.Server == "" {
		return nil, fmt.Errorf("kubeconfig: cluster %q has no server", ctx.Cluster)
	}

	user := users[ctx.User]

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	caPEM, err := inlineOrFile(cluster.CertificateAuthorityData, cluster.CertificateAuthority)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: cluster %q ca: %w", ctx.Cluster, err)
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("kubeconfig: cluster %q ca has no certificates", ctx.Cluster)
		}
		tlsCfg.RootCAs = pool
	}
	if cluster.InsecureSkipTLSVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	certPEM, err := inlineOrFile(user.ClientCertificateData, user.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: user %q certificate: %w", ctx.User, err)
	}
	keyPEM, err := inlineOrFile(user.ClientKeyData, user.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: user %q key: %w", ctx.User, err)
	}
	switch {
	case len(certPEM) > 0 && len(keyPEM) > 0:
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig: user %q key pair: %w", ctx.User, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	case len(certPEM) > 0 || len(keyPEM) > 0:
		return nil, fmt.Errorf("kubeconfig: user %q has only one of client-certificate/client-key", ctx.User)
	}

	token := user.Token
	cfg := &Config{BaseURL: strings.TrimRight(cluster.Server, "/"), TLS: tlsCfg}
	if token != "" {
		cfg.Token = func() (string, error) { return token, nil }
	}
	return cfg, nil
}

// inlineOrFile returns base64-deoded inline data when set, else the file's
// contents, else nil. File paths are rejected when they are empty.
func inlineOrFile(inline, file string) ([]byte, error) {
	if inline != "" {
		return base64.StdEncoding.DecodeString(inline)
	}
	if file != "" {
		return os.ReadFile(file)
	}
	return nil, nil
}

// Only the fields the controller can consume; everything else in a
// kubeconfig is ignored rather than rejected, so admin kubeconfigs and
// kind's generated one both load.
type kubeconfig struct {
	CurrentContext string         `yaml:"current-context"`
	Contexts       []namedContext `yaml:"contexts"`
	Clusters       []namedCluster `yaml:"clusters"`
	Users          []namedUser    `yaml:"users"`
}

type namedContext struct {
	Name    string      `yaml:"name"`
	Context kubeContext `yaml:"context"`
}

type kubeContext struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type namedCluster struct {
	Name    string      `yaml:"name"`
	Cluster kubeCluster `yaml:"cluster"`
}

type kubeCluster struct {
	Server                   string `yaml:"server"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
}

type namedUser struct {
	Name string   `yaml:"name"`
	User kubeUser `yaml:"user"`
}

type kubeUser struct {
	Token                 string `yaml:"token"`
	ClientCertificate     string `yaml:"client-certificate"`
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKey             string `yaml:"client-key"`
	ClientKeyData         string `yaml:"client-key-data"`
}
