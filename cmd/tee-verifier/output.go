package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/0xsequence/tee-verifier/nitro"
)

type Response struct {
	Method      string
	Path        string
	Signature   string // Oms-Wallet-Signature request header, "" if absent
	RequestBody string
	Status      int
	Body        string
}

// VerifyUserData checks that userData is "Sequence/<N>:<base64(sha256(preimage))>"
// where the preimage for the supported versions is:
//
//	1: METHOD + " " + PATH + "\n" + RequestBody + "\n" + Body
//	2: METHOD + " " + PATH + "\n" + Signature + "\n" + RequestBody + "\n" + Body
func (r *Response) VerifyUserData(userData []byte) error {
	prefix, encoded, ok := strings.Cut(string(userData), ":")
	if !ok {
		return fmt.Errorf("missing version prefix")
	}
	num, ok := strings.CutPrefix(prefix, "Sequence/")
	version, err := strconv.ParseUint(num, 10, 8)
	if !ok || err != nil {
		return fmt.Errorf("invalid version prefix %q", prefix)
	}
	expected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("invalid digest encoding: %w", err)
	}

	h := sha256.New()
	switch version {
	case 1:
		fmt.Fprintf(h, "%s %s\n%s\n%s", r.Method, r.Path, r.RequestBody, r.Body)
	case 2:
		fmt.Fprintf(h, "%s %s\n%s\n%s\n%s", r.Method, r.Path, r.Signature, r.RequestBody, r.Body)
	default:
		return fmt.Errorf("unsupported version %d", version)
	}
	if !bytes.Equal(expected, h.Sum(nil)) {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}

type Output struct {
	ModuleID  string    `json:"module_id"`
	Timestamp time.Time `json:"timestamp"`
	PCR0      string    `json:"pcr0"`
	Nonce     string    `json:"nonce"`
	UserData  string    `json:"user_data"`

	RootCertSubject     string `json:"root_cert_subject"`
	RootCertFingerprint string `json:"root_cert_fingerprint"`

	AttestationValid bool  `json:"attestation_valid"`
	SignatureValid   bool  `json:"signature_valid"`
	UserDataValid    *bool `json:"user_data_valid,omitempty"`

	ResponseStatus int    `json:"response_status,omitempty"`
	ResponseBody   string `json:"response_body,omitempty"`
}

func (o *Output) WriteTable(w io.Writer) error {
	table := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(table, "Module ID\t%s\n", o.ModuleID)
	fmt.Fprintf(table, "Timestamp\t%s\n", o.Timestamp)
	fmt.Fprintf(table, "PCR0\t%s\n", o.PCR0)
	fmt.Fprintf(table, "Nonce\t%s\n", o.Nonce)
	fmt.Fprintf(table, "UserData\t%s\n", o.UserData)
	fmt.Fprintf(table, "Root Cert Subject\t%s\n", o.RootCertSubject)
	fmt.Fprintf(table, "Root Cert Fingerprint\t%s\n", o.RootCertFingerprint)
	fmt.Fprintf(table, "Attestation Valid\t%t\n", o.AttestationValid)
	fmt.Fprintf(table, "Signature Valid\t%t\n", o.SignatureValid)
	if o.UserDataValid != nil {
		fmt.Fprintf(table, "UserData Valid\t%t\n", *o.UserDataValid)
	}
	if o.ResponseStatus != 0 {
		fmt.Fprintf(table, "Response Status\t%d\n", o.ResponseStatus)
	}
	if o.ResponseBody != "" {
		fmt.Fprintf(table, "Response Body\t%s\n", o.ResponseBody)
	}
	return table.Flush()
}

func outputFromAttestation(att *nitro.SignedAttestation, resp *Response, validateOpts ...nitro.ValidateOption) *Output {
	out := &Output{
		ModuleID:            att.ModuleID,
		Timestamp:           att.Timestamp,
		PCR0:                att.PCRs[0],
		Nonce:               string(att.Nonce),
		UserData:            string(att.UserData),
		RootCertSubject:     att.CABundle[0].Subject.String(),
		RootCertFingerprint: att.RootCertFingerprint(),
	}

	if err := att.Validate(validateOpts...); err == nil {
		out.AttestationValid = true
	} else {
		fmt.Fprintf(os.Stderr, "invalid attestation: %s\n", err)
	}

	if err := att.Verify(); err == nil {
		out.SignatureValid = true
	} else {
		fmt.Fprintf(os.Stderr, "invalid signature: %s\n", err)
	}

	if resp != nil {
		out.ResponseStatus = resp.Status
		out.ResponseBody = resp.Body

		if err := resp.VerifyUserData(att.UserData); err == nil {
			out.UserDataValid = ptr(true)
		} else {
			out.UserDataValid = ptr(false)
			fmt.Fprintf(os.Stderr, "invalid user data: %s\n", err)
		}
	}

	return out
}

func ptr[T any](v T) *T {
	return &v
}
