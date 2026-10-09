package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policybundle"
)

var version = "dev"

func main() {
	push := flag.Bool("push", false, "Push .wasm policy to OCI registry")
	pull := flag.Bool("pull", false, "Pull .wasm policy from OCI registry")
	ref := flag.String("ref", "", "OCI reference (e.g., ghcr.io/org/policy:v1)")
	wasmFile := flag.String("wasm", "", "Path to .wasm file (push: input, pull: output)")
	name := flag.String("name", "warmor-policy", "Policy name metadata")
	policyVersion := flag.String("policy-version", "1.0.0", "Policy version metadata")
	description := flag.String("description", "", "Policy description metadata")
	keygen := flag.Bool("keygen", false, "Generate an ed25519 signing key pair at --sign-key and --verify-key")
	signKey := flag.String("sign-key", "", "Path to ed25519 private key PEM (PKCS#8) used to sign on push")
	verifyKey := flag.String("verify-key", "", "Path to ed25519 public key PEM (PKIX) used to verify on pull")
	allowUnsigned := flag.Bool("allow-unsigned", false, "Push without signing (INSECURE: such bundles only pull with --insecure-skip-verify)")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "Pull without verifying the bundle signature (INSECURE)")
	maxWasmSize := flag.Int64("max-wasm-size", policybundle.DefaultMaxWasmSize, "Maximum wasm layer size in bytes accepted on pull")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-policy-bundle [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Package compiled .wasm policies as OCI artifacts for registry push/pull.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-bundle --keygen --sign-key signing.key --verify-key signing.pub\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-bundle --push --ref ghcr.io/org/policy:v1 --wasm policy.wasm --sign-key signing.key\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-bundle --pull --ref ghcr.io/org/policy:v1 --wasm policy.wasm --verify-key signing.pub\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-bundle --pull --ref ghcr.io/org/policy@sha256:... --wasm policy.wasm --verify-key signing.pub\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("warmor-policy-bundle %s\n", version)
		os.Exit(0)
	}

	if *keygen {
		if *push || *pull {
			fmt.Fprintf(os.Stderr, "error: --keygen cannot be combined with --push or --pull\n")
			os.Exit(1)
		}
		if err := generateKeys(*signKey, *verifyKey); err != nil {
			fmt.Fprintf(os.Stderr, "error: keygen: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Wrote private key %s and public key %s\n", *signKey, *verifyKey)
		return
	}

	if !*push && !*pull {
		fmt.Fprintf(os.Stderr, "error: specify --push or --pull\n")
		flag.Usage()
		os.Exit(1)
	}
	if *push && *pull {
		fmt.Fprintf(os.Stderr, "error: specify only one of --push or --pull\n")
		os.Exit(1)
	}
	if *ref == "" {
		fmt.Fprintf(os.Stderr, "error: --ref is required\n")
		os.Exit(1)
	}
	if *wasmFile == "" {
		fmt.Fprintf(os.Stderr, "error: --wasm is required\n")
		os.Exit(1)
	}

	ctx := context.Background()

	if *push {
		opts := policybundle.PushOptions{AllowUnsigned: *allowUnsigned}
		switch {
		case *signKey != "":
			sk, err := crypto.LoadSigningKey(*signKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: load signing key: %v\n", err)
				os.Exit(1)
			}
			opts.SigningKey = sk
		case !*allowUnsigned:
			fmt.Fprintf(os.Stderr, "error: --sign-key is required for push (or pass --allow-unsigned)\n")
			os.Exit(1)
		}
		cfg := policybundle.BundleConfig{
			Name:        *name,
			Version:     *policyVersion,
			Description: *description,
		}
		desc, err := policybundle.Push(ctx, *ref, *wasmFile, cfg, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: push: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Pushed %s → %s (digest: %s)\n", *wasmFile, *ref, desc.Digest)
	}

	if *pull {
		opts := policybundle.PullOptions{InsecureSkipVerify: *insecureSkipVerify, MaxWasmSize: *maxWasmSize}
		switch {
		case *verifyKey != "":
			pub, err := crypto.LoadPublicKey(*verifyKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: load verify key: %v\n", err)
				os.Exit(1)
			}
			opts.PublicKey = pub
		case !*insecureSkipVerify:
			fmt.Fprintf(os.Stderr, "error: --verify-key is required for pull (or pass --insecure-skip-verify)\n")
			os.Exit(1)
		}
		desc, err := policybundle.Pull(ctx, *ref, *wasmFile, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: pull: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Pulled %s → %s (digest: %s)\n", *ref, *wasmFile, desc.Digest)
	}
}

// generateKeys writes a new ed25519 key pair: the private key (0600) to
// privPath and the public key to pubPath. Existing files are not
// overwritten.
func generateKeys(privPath, pubPath string) error {
	if privPath == "" || pubPath == "" {
		return fmt.Errorf("--sign-key and --verify-key must name the output files")
	}
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		return err
	}
	privPEM, err := sk.MarshalPrivateKey()
	if err != nil {
		return err
	}
	pubPEM, err := sk.MarshalPublicKey()
	if err != nil {
		return err
	}
	if err := writeNew(privPath, privPEM, 0600); err != nil {
		return err
	}
	if err := writeNew(pubPath, pubPEM, 0644); err != nil {
		os.Remove(privPath)
		return err
	}
	return nil
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
