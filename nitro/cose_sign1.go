package nitro

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type COSESign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected struct{}
	Payload     []byte
	Signature   []byte
}

func (c *COSESign1) Verify(key crypto.PublicKey) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type: %T", key)
	}

	type sigStructure struct {
		_             struct{} `cbor:",toarray"`
		Context       string
		BodyProtected []byte
		ExternalAAD   []byte
		Payload       []byte
	}
	msg, err := cbor.Marshal(sigStructure{
		Context:       "Signature1",
		BodyProtected: c.Protected,
		ExternalAAD:   []byte{},
		Payload:       c.Payload,
	})
	if err != nil {
		return err
	}

	hash := crypto.SHA384.New()
	if _, err := hash.Write(msg); err != nil {
		return err
	}
	digest := hash.Sum(nil)

	size := len(c.Signature)
	r := big.NewInt(0).SetBytes(c.Signature[:size/2])
	s := big.NewInt(0).SetBytes(c.Signature[size/2:])

	if !ecdsa.Verify(ecdsaKey, digest, r, s) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
