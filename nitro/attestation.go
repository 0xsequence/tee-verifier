package nitro

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Attestation struct {
	ModuleID    string
	Timestamp   time.Time
	Digest      string
	PCRs        map[int]string
	Certificate *x509.Certificate
	CABundle    []*x509.Certificate
	PublicKey   *rsa.PublicKey
	UserData    []byte
	Nonce       []byte
}

func (d *Attestation) FromBytes(data []byte) (err error) {
	type rawDoc struct {
		ModuleID    string            `cbor:"module_id"`
		Timestamp   uint64            `cbor:"timestamp"`
		Digest      string            `cbor:"digest"`
		PCRs        map[int][]byte    `cbor:"pcrs"`
		Certificate []byte            `cbor:"certificate"`
		CABundle    []cbor.RawMessage `cbor:"cabundle"`
		PublicKey   []byte            `cbor:"public_key"`
		UserData    []byte            `cbor:"user_data"`
		Nonce       []byte            `cbor:"nonce"`
	}

	var raw rawDoc
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}

	d.ModuleID = raw.ModuleID
	d.Timestamp = time.Unix(int64(raw.Timestamp/1000), int64(raw.Timestamp%1000)*1000000)
	d.Digest = raw.Digest
	d.PCRs = make(map[int]string)
	for k, v := range raw.PCRs {
		d.PCRs[k] = hex.EncodeToString(v)
	}
	d.Certificate, err = x509.ParseCertificate(raw.Certificate)
	if err != nil {
		return err
	}

	d.CABundle = make([]*x509.Certificate, len(raw.CABundle))
	for i, v := range raw.CABundle {
		var der []byte
		if err := cbor.Unmarshal(v, &der); err != nil {
			return err
		}
		d.CABundle[i], err = x509.ParseCertificate(der)
		if err != nil {
			return err
		}
	}

	key, err := x509.ParsePKIXPublicKey(raw.PublicKey)
	if err != nil {
		return err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key type: %T", key)
	}
	d.PublicKey = rsaKey
	d.UserData = raw.UserData
	d.Nonce = raw.Nonce
	return nil
}

type validateConfig struct {
	time            time.Time
	rootFingerprint string
	expectedPCRs    map[int]string
	expectedNonce   []byte
}

type ValidateOption func(*validateConfig)

func WithTime(t time.Time) ValidateOption {
	return func(o *validateConfig) {
		o.time = t
	}
}

func WithRootFingerprint(fp string) ValidateOption {
	return func(o *validateConfig) {
		o.rootFingerprint = fp
	}
}

func WithExpectedNonce(nonce []byte) ValidateOption {
	return func(o *validateConfig) {
		o.expectedNonce = nonce
	}
}

func WithExpectedPCRs(pcrs map[int]string) ValidateOption {
	return func(o *validateConfig) {
		o.expectedPCRs = pcrs
	}
}

func (d *Attestation) Validate(opts ...ValidateOption) error {
	cfg := &validateConfig{
		time: time.Now(),
		// From https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process
		rootFingerprint: "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if d.RootCertFingerprint() != cfg.rootFingerprint {
		return fmt.Errorf("invalid root certificate")
	}

	roots := x509.NewCertPool()
	roots.AddCert(d.CABundle[0])
	intermediates := x509.NewCertPool()
	for _, cert := range d.CABundle[1:] {
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   cfg.time,
	}
	if _, err := d.Certificate.Verify(verifyOpts); err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	for k, v := range cfg.expectedPCRs {
		if d.PCRs[k] != v {
			return fmt.Errorf("invalid PCR%d: %s", k, d.PCRs[k])
		}
	}
	if cfg.expectedNonce != nil && !bytes.Equal(d.Nonce, cfg.expectedNonce) {
		return fmt.Errorf("invalid nonce: %s", d.Nonce)
	}
	return nil
}

func (d *Attestation) RootCertFingerprint() string {
	fingerprint := sha256.Sum256(d.CABundle[0].Raw)
	return hex.EncodeToString(fingerprint[:])
}
