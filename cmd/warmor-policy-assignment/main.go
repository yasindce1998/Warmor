// warmor-policy-assignment runs in the separate deployment-signing environment,
// never in the central relay or agent. It does not allocate sequences or keys.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/wasm"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("warmor-policy-assignment", flag.ContinueOnError)
	intent := fs.String("intent", "", "Deployment JSON containing exact target, policy metadata, fresh allocated sequence, expiry and optional rollback")
	module := fs.String("wasm", "", "Artifact-author-approved WASM with build metadata and explicit ABI")
	artifactKey := fs.String("artifact-public-key", "", "Artifact public key PKIX PEM (never its private key)")
	signKey := fs.String("assignment-private-key", "", "Separate assignment private key PKCS8 PEM; loaded only in this offline deployment signer")
	output := fs.String("out", "", "New bundle output path (refuses overwrite)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *intent == "" || *module == "" || *artifactKey == "" || *signKey == "" || *output == "" {
		return fmt.Errorf("--intent, --wasm, --artifact-public-key, --assignment-private-key and --out are required")
	}
	data, err := crypto.ReadFileLimited(*intent, assignment.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	var d assignment.Deployment
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing intent data")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	pub, err := crypto.LoadPublicKey(*artifactKey)
	if err != nil {
		return err
	}
	info, err := os.Stat(*signKey)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return fmt.Errorf("assignment private key must be a private regular file (mode 0600)")
	}
	key, err := crypto.LoadSigningKey(*signKey)
	if err != nil {
		return err
	}
	if bytes.Equal(pub, key.Public) {
		return fmt.Errorf("artifact and assignment keys must be distinct")
	}
	wasmBytes, err := crypto.ReadFileLimited(*module, wasm.MaxPolicySize)
	if err != nil {
		return err
	}
	sigFile, err := crypto.ReadFileLimited(*module+".sig", crypto.MaxPolicySignatureFileSize)
	if err != nil {
		return err
	}
	if err := crypto.VerifyPolicySignature(pub, wasmBytes, sigFile); err != nil {
		return err
	}
	sig, err := crypto.DecodePolicySignature(sigFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{PoolSize: 1})
	if err != nil {
		return err
	}
	defer rt.Close(context.Background())
	if err := rt.LoadPolicyBytes(ctx, wasmBytes); err != nil {
		return err
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		return err
	}
	defer pool.Close(context.Background())
	if err := pool.CheckAssignment(d.Policy); err != nil {
		return err
	}
	envelope, err := assignment.Sign(key.Private, d)
	if err != nil {
		return err
	}
	wire, err := assignment.Encode(envelope)
	if err != nil {
		return err
	}
	bundle := assignment.Bundle{Envelope: wire, WASM: wasmBytes, ArtifactSignature: sig}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	if _, err := assignment.DecodeBundle(encoded); err != nil {
		return err
	}
	f, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(*output)
		}
	}()
	if _, err := f.Write(encoded); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
