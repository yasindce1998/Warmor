package assignment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// Bundle relays independently signed artifact bytes and exact encoded intent.
// No private key is needed on a relay. The envelope is base64 in JSON so its
// canonical transport bytes survive an outer JSON encoder unchanged.
type Bundle struct {
	Envelope          []byte `json:"envelope"`
	WASM              []byte `json:"wasm"`
	ArtifactSignature []byte `json:"artifact_signature"`
}

const MaxBundleBytes = 90 << 20
const ProtocolHeader = "X-Warmor-Signed-Assignment"

func DecodeBundle(data []byte) (Bundle, error) {
	if len(data) > MaxBundleBytes {
		return Bundle{}, ErrInvalid
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, err
	}
	canonical, err := json.Marshal(b)
	if err != nil || !bytes.Equal(canonical, data) {
		return Bundle{}, fmt.Errorf("%w: noncanonical deployment bundle", ErrInvalid)
	}
	if _, err := Decode(b.Envelope); err != nil {
		return Bundle{}, err
	}
	if len(b.WASM) == 0 || len(b.WASM) > 64<<20 || len(b.ArtifactSignature) != ed25519.SignatureSize {
		return Bundle{}, ErrInvalid
	}
	return b, nil
}
