package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/0xsequence/tee-verifier/nitro"
)

type Response struct {
	Digest []byte `json:"digest"`
	Status int    `json:"status"`
	Body   string `json:"body"`
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
	}

	if err := att.Verify(); err == nil {
		out.SignatureValid = true
	}

	if resp != nil {
		out.ResponseStatus = resp.Status
		out.ResponseBody = resp.Body

		if resp.Digest != nil && att.UserData != nil && strings.HasPrefix(string(att.UserData), "Sequence/1:") {
			expectedDigest, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(att.UserData), "Sequence/1:"))
			if bytes.Equal(expectedDigest, resp.Digest) {
				out.UserDataValid = ptr(true)
			} else {
				out.UserDataValid = ptr(false)
			}
		}
	}

	return out
}

func ptr[T any](v T) *T {
	return &v
}
