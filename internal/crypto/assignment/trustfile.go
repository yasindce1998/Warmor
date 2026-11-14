package assignment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	policycrypto "github.com/yasindce1998/warmor/internal/crypto"
)

// ParseTrustFile reads PUBLIC relay admission grants only. Agent configuration
// independently constrains its own audience/compiler/posture and clock.
func ParseTrustFile(data []byte) (Trust, error) {
	var entries []struct {
		ID          string `json:"id"`
		PublicKey   string `json:"public_key"`
		Target      Target `json:"target"`
		CanRollback bool   `json:"can_rollback"`
	}
	if len(data) > 256<<10 {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&entries); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, ErrInvalid
	}
	if len(entries) == 0 || len(entries) > 256 {
		return nil, ErrInvalid
	}
	trust := Trust{}
	for _, e := range entries {
		if !validText(e.ID, 128) || e.Target.Validate() != nil {
			return nil, ErrInvalid
		}
		if _, exists := trust[e.ID]; exists {
			return nil, errors.New("duplicate assignment key ID")
		}
		pub, err := policycrypto.LoadPublicKeyFromPEM([]byte(e.PublicKey))
		if err != nil {
			return nil, err
		}
		trust[e.ID] = Key{Public: pub, Target: e.Target, CanRollback: e.CanRollback}
	}
	return trust, nil
}
