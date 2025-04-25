package nitro

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type SignedAttestation struct {
	Attestation
	sign1 *COSESign1
}

func Parse(data []byte) (*SignedAttestation, error) {
	var sign1 COSESign1
	if err := cbor.Unmarshal(data, &sign1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE Sign1: %w", err)
	}

	var doc Attestation
	if err := doc.FromBytes(sign1.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	att := &SignedAttestation{
		Attestation: doc,
		sign1:       &sign1,
	}
	return att, nil
}

func (s *SignedAttestation) Verify() error {
	return s.sign1.Verify(s.Certificate.PublicKey)
}
