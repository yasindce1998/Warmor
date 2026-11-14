package assignment

import (
	"bytes"
	"encoding/json"
	"testing"

	policycrypto "github.com/yasindce1998/warmor/internal/crypto"
)

func TestBundleCanonicalTransportAndPublicTrustFile(t *testing.T) {
	d, module, private, _, _ := fixture(t)
	envelope := mustSign(t, private, d)
	wire, err := Encode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{Envelope: wire, WASM: module, ArtifactSignature: envelope.Signature}
	wire, err = json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBundle(wire); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(wire), '\n'), bytes.Replace(wire, []byte(`"envelope":`), []byte(`"unknown":1,"envelope":`), 1), []byte(`null`)} {
		if _, err := DecodeBundle(bad); err == nil {
			t.Fatal("ambiguous bundle accepted")
		}
	}
	key, err := policycrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	entries := []map[string]any{{"id": "deployment", "public_key": string(pub), "target": d.Target, "can_rollback": false}}
	data, _ := json.Marshal(entries)
	trust, err := ParseTrustFile(data)
	if err != nil || !bytes.Equal(trust["deployment"].Public, key.Public) {
		t.Fatal(err)
	}
	entries = append(entries, entries[0])
	data, _ = json.Marshal(entries)
	if _, err := ParseTrustFile(data); err == nil {
		t.Fatal("duplicate trust ID accepted")
	}
	if _, err := ParseTrustFile([]byte(`[]`)); err == nil {
		t.Fatal("empty relay trust accepted")
	}
}
