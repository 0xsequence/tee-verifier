# TEE verifier

Library and CLI tool for verifying TEE (Trusted Execution Environment) enclave attestations. Currently only AWS Nitro Enclaves is supported.

## Install

Install using Go:

```
go install github.com/0xsequence/tee-verifier/cmd/tee-verifier@latest
```

Or, build from source and install (Linux & macOS only):

```
git clone https://github.com/0xsequence/tee-verifier
cd tee-verifier
make
sudo make install
```

## CLI usage

Example verifying the [Sequence WaaS enclave](https://github.com/0xsequence/waas-authenticator) attestation:

```
tee-verifier https://waas.sequence.app/health
```

You can compare the PCR0 attested by the deployed service against the measurement listed at https://github.com/0xsequence/waas-authenticator/releases. Building the application from source at the specific git tag should result in the same PCR0 measurement. Read more about the way attestation works below.

### Full usage:

```
NAME:
   tee-verifier - Verify enclave attestation documents

USAGE:
   tee-verifier [global options] URL

GLOBAL OPTIONS:
   --json                                                     output in JSON format (default: false)
   --pcr0 string                                              expected PCR0 value
   --nonce string                                             expected nonce
   --root-fingerprint string                                  expected root certificate fingerprint
   --data string, -d string                                   HTTP POST data
   --header string, -H string [ --header string, -H string ]  extra HTTP request header, "Name: value" (e.g. Oms-Wallet-Signature)
   --verbose, -v                                              verbose output (default: false)
   --version, -V                                              show version information
   --help, -h                                                 show help
```

To verify a signed request, pass the signature header so it is both sent and included in the `UserData` check:

```
tee-verifier -d '{...}' -H 'Oms-Wallet-Signature: 0x...' https://waas.sequence.app/rpc/WaasAuthenticator/RegisterSession
```

## How it works

Applications like [Sequence WaaS](https://github.com/0xsequence/waas-authenticator) run inside a secure, isolated environment known as a **Nitro Enclave**, built on the [AWS Nitro system](https://aws.amazon.com/ec2/nitro/). The Nitro Enclave ensures strong isolation and allows cryptographic attestation of the software running inside it.

To verify the enclave’s integrity, the Nitro Hypervisor generates cryptographic **measurements** of the enclave image. One such measurement, **PCR0**, is a SHA-384 hash over the entire initial image file loaded into the enclave. These measurements are included in an **attestation document**, which is cryptographically signed by a certificate chain rooted at the Amazon CA. [AWS's cryptographic attestation documentation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html) explains this process in more detail.

The attestation document is a Base64-encoded [COSE_Sign1](https://datatracker.ietf.org/doc/html/rfc8152) structure, with content in CBOR format. It includes several fields that are signed using a leaf certificate, which is itself signed by the full certificate chain (the `CABundle`) leading to the AWS root certificate.

Key attested fields include:

- `Timestamp`: Time the attestation was generated
- `PCRs`: Platform Configuration Register values, including PCR0
- `Certificate`: The leaf certificate used to sign the COSE structure
- `CABundle`: Full certificate chain ending with the AWS root certificate
- `Nonce`: A random value included by the verifier to ensure freshness; matches the `X-Attestation-Nonce` HTTP request header
- `UserData`: Application-specific field; in Sequence’s case, this contains a content hash representing the request and response, ensuring binding to a specific transaction

Each request to a Sequence enclave triggers a fresh attestation, which is returned in the `X-Attestation-Document` HTTP response header.

The verifier performs multiple levels of validation:

1. **Semantic validation**: The attestation’s structure and field presence are verified
2. **PCR validation**: Measured PCRs are compared against expected values, ensuring the enclave runs the intended code
3. **Signature validation**: The COSE signature is verified using the included certificate
4. **Certificate chain validation**: The chain is validated up to the root, ensuring trust in the signer
5. **Root of trust validation**: The fingerprint of the root certificate is compared against [AWS's published CA fingerprint](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process)
6. **Content binding and replay prevention**: `UserData` must contain the expected request/response hash, and `Nonce` must match the original request header, preventing reuse of attestations across requests


### UserData format

Syntax is `"Sequence/" + Version + ":" + base64(sha256(Preimage))`. The verifier accepts versions 1 and 2 and reports any other version as invalid.

Version 1:

```
"Sequence/1:" + base64(sha256(HttpMethod + " " + HttpPath + "\n" + RequestBody + "\n" + ResponseBody))
```

Version 2 additionally binds the request signature, so a TLS edge cannot re-sign the request with its own key undetected. `Signature` is the raw value of the `Oms-Wallet-Signature` request header exactly as sent, or the empty string if the request has none:

```
"Sequence/2:" + base64(sha256(HttpMethod + " " + HttpPath + "\n" + Signature + "\n" + RequestBody + "\n" + ResponseBody))
```

## Acknowledgements

- https://github.com/anjuna-security/go-nitro-attestation
- https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/


