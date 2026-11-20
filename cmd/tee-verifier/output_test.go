package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func userData(version int, preimage string) []byte {
	sum := sha256.Sum256([]byte(preimage))
	return []byte(fmt.Sprintf("Sequence/%d:%s", version, base64.StdEncoding.EncodeToString(sum[:])))
}

func TestResponse_VerifyUserData(t *testing.T) {
	signed := &Response{
		Method:      "POST",
		Path:        "/rpc/WaasAuthenticator/RegisterSession",
		Signature:   "0xsig",
		RequestBody: `{"a":1}`,
		Body:        `{"ok":true}`,
	}
	unsigned := *signed
	unsigned.Signature = ""

	v1 := "POST /rpc/WaasAuthenticator/RegisterSession\n{\"a\":1}\n{\"ok\":true}"
	v2Signed := "POST /rpc/WaasAuthenticator/RegisterSession\n0xsig\n{\"a\":1}\n{\"ok\":true}"
	v2Unsigned := "POST /rpc/WaasAuthenticator/RegisterSession\n\n{\"a\":1}\n{\"ok\":true}"

	t.Run("v1 valid", func(t *testing.T) {
		if err := signed.VerifyUserData(userData(1, v1)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("v2 valid with header", func(t *testing.T) {
		if err := signed.VerifyUserData(userData(2, v2Signed)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("v2 valid without header", func(t *testing.T) {
		if err := unsigned.VerifyUserData(userData(2, v2Unsigned)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("v2 tampered header", func(t *testing.T) {
		tampered := *signed
		tampered.Signature = "0xevil"
		if err := tampered.VerifyUserData(userData(2, v2Signed)); err == nil {
			t.Fatal("expected digest mismatch")
		}
	})

	t.Run("v3 unsupported", func(t *testing.T) {
		if err := signed.VerifyUserData(userData(3, v2Signed)); err == nil {
			t.Fatal("expected unsupported version")
		}
	})

	t.Run("garbage prefix", func(t *testing.T) {
		for _, ud := range []string{"", "Sequence/1", "Sequence/x:AAAA", "Other/1:AAAA", "Sequence/1:not base64!"} {
			if err := signed.VerifyUserData([]byte(ud)); err == nil {
				t.Fatalf("%q: expected error", ud)
			}
		}
	})
}

func TestFetchAttestationFromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-attestation-document", "doc")
		w.Write([]byte(r.Header.Get("Oms-Wallet-Signature")))
	}))
	defer srv.Close()

	t.Run("header passthrough", func(t *testing.T) {
		doc, resp, err := fetchAttestationFromURL(srv.URL+"/rpc", "", `{}`, []string{"Oms-Wallet-Signature: 0xsig"})
		if err != nil {
			t.Fatal(err)
		}
		if doc != "doc" || resp.Method != "POST" || resp.Path != "/rpc" || resp.RequestBody != `{}` || resp.Signature != "0xsig" || resp.Body != "0xsig" {
			t.Fatalf("unexpected response: %+v", resp)
		}
	})

	t.Run("no header", func(t *testing.T) {
		_, resp, err := fetchAttestationFromURL(srv.URL, "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Method != "GET" || resp.Signature != "" {
			t.Fatalf("unexpected response: %+v", resp)
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		if _, _, err := fetchAttestationFromURL(srv.URL, "", "", []string{"nocolon"}); err == nil {
			t.Fatal("expected error")
		}
	})
}
