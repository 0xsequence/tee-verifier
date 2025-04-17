# TEE verifier

Library and CLI tool for verifying TEE (Trusted Execution Environment) enclave attestations. Currently only AWS Nitro Enclaves is supported.

## Install

```
go get https://github.com/0xsequence/tee-verifier
```

## CLI usage

```
NAME:
   tee-verifier - Verify attestation documents

USAGE:
   tee-verifier [global options] URL

GLOBAL OPTIONS:
   --json          output in JSON format (default: false)
   --pcr0 string   expected PCR0 value
   --nonce string  expected nonce
   --help, -h      show help
```

## Acknowledgements

- https://github.com/anjuna-security/go-nitro-attestation
- https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/


