package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/0xsequence/tee-verifier/nitro"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:      "tee-verifier",
		Usage:     "Verify attestation documents",
		ArgsUsage: "URL",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "output in JSON format",
			},
			&cli.StringFlag{
				Name:  "pcr0",
				Usage: "expected PCR0 value",
			},
			&cli.StringFlag{
				Name:  "nonce",
				Usage: "expected nonce",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			input := cmd.Args().First()
			if input == "" {
				return fmt.Errorf("input file/URL is required")
			}

			var (
				doc string
				err error
			)
			if strings.HasPrefix(input, "http") || strings.HasPrefix(input, "https") {
				doc, err = fetchAttestationFromURL(input, cmd.String("nonce"))
				if err != nil {
					return fmt.Errorf("failed to download file: %w", err)
				}
			} else if input == "-" {
				doc, err = fetchAttestationFromStdin()
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
			} else {
				docBytes, err := os.ReadFile(input)
				if err != nil {
					return fmt.Errorf("failed to read file: %w", err)
				}
				doc = string(docBytes)
			}

			docBytes, err := base64.StdEncoding.DecodeString(doc)
			if err != nil {
				return fmt.Errorf("failed to decode attestation document: %w", err)
			}

			att, err := nitro.Parse(docBytes)
			if err != nil {
				return fmt.Errorf("failed to parse attestation document: %w", err)
			}

			opts := []nitro.ValidateOption{}
			if pcr0 := cmd.String("pcr0"); pcr0 != "" {
				opts = append(opts, nitro.WithExpectedPCRs(map[int]string{
					0: pcr0,
				}))
			}
			if nonce := cmd.String("nonce"); nonce != "" {
				opts = append(opts, nitro.WithExpectedNonce([]byte(nonce)))
			}

			out := outputFromAttestation(att, opts...)
			if cmd.Bool("json") {
				json.NewEncoder(os.Stdout).Encode(out)
			} else {
				out.WriteTable(os.Stdout)
			}

			if !out.AttestationValid || !out.SignatureValid {
				os.Exit(1)
			}

			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fetchAttestationFromURL(url string, nonce string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	if nonce != "" {
		req.Header.Set("x-attestation-nonce", nonce)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download file: %w", err)
	}

	doc := resp.Header.Get("x-attestation-document")
	if doc == "" {
		return "", fmt.Errorf("no attestation document found")
	}

	return doc, nil
}

func fetchAttestationFromStdin() (string, error) {
	doc, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read from stdin: %w", err)
	}

	return string(doc), nil
}
