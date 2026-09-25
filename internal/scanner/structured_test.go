package scanner

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"secret-sniffer/internal/detectors"
)

func TestStructuredProviderDetection(t *testing.T) {
	github := "ghp_aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD3fG5hJ7"
	cohere := "v9K2pQ7mX4rT8nW3b6Y1hJ5kL0sD2fG8"
	cases := []struct {
		name, input, id, secret, format string
		line, column                    int
	}{
		{"JSON escaped signature", `{"token":"gh\u0070_` + strings.TrimPrefix(github, "ghp_") + `"}`, "github-token", github, "json", 1, 11},
		{"JSON non-generic field", `{"github_token":"gh\u0070_` + strings.TrimPrefix(github, "ghp_") + `"}`, "github-token", github, "json", 1, 18},
		{"YAML folded scalar", "token: >-\n  " + github + "\n", "github-token", github, "yaml", 1, 8},
		{"YAML literal scalar", "token: |\n  " + github + "\n", "github-token", github, "yaml", 1, 8},
		{"YAML block contextual key", "cohere:\n  api_key: |\n    " + cohere + "\n", "cohere-api-key", cohere, "yaml", 2, 12},
		{"JSON escaped context and key", `{"coh\u0065re":{"api_k\u0065y":"` + cohere + `"}}`, "cohere-api-key", cohere, "json", 1, 33},
		{"JSON raw prefix replaced", `{"token":"` + github + `\u0061tail"}`, "github-token", github + "atail", "json", 1, 11},
		{"JSON trailing provider selector", `{"api_key":"` + cohere + `","provider":"coh\u0065re"}`, "cohere-api-key", cohere, "json", 1, 13},
	}
	registry := detectors.DefaultRegistry()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, encoded := range []bool{false, true} {
				input := tc.input
				chain := []string{tc.format}
				line, column := tc.line, tc.column
				if encoded {
					input = base64.StdEncoding.EncodeToString([]byte(input))
					chain = append([]string{"base64"}, chain...)
					line, column = 1, 1
				}
				got := New(Config{}, registry).ScanContent(context.Background(), "fixture", []byte(input))
				if len(got) != 1 {
					t.Fatalf("encoded=%v: expected one provider finding, got %+v", encoded, got)
				}
				f := got[0]
				if f.DetectorID != tc.id || f.Secret != tc.secret {
					t.Errorf("wrong credential: %+v", f)
				}
				if f.Line != line || f.Column != column {
					t.Errorf("encoded=%v: location %d:%d, want %d:%d", encoded, f.Line, f.Column, line, column)
				}
				if f.Provenance == nil || !reflect.DeepEqual(f.Provenance.DecoderChain, chain) {
					t.Errorf("encoded=%v: wrong provenance: %+v", encoded, f.Provenance)
				}
			}
		})
	}
}

func TestStructuredProviderRecordIsolation(t *testing.T) {
	value := "v9K2pQ7mX4rT8nW3b6Y1hJ5kL0sD2fG8"
	for _, input := range []string{
		`[{"provider":"coh\u0065re"},{"api_key":"` + value + `"}]`,
		`{"coh\u0065re":{"enabled":true},"other":{"api_key":"` + value + `"}}`,
		"cohere:\n  description: \"some\\u0020text\"\n---\napi_key: " + value,
		`["coh\u0065re","api_key=` + value + `"]`,
	} {
		for _, f := range New(Config{}, detectors.DefaultRegistry()).ScanContent(context.Background(), "fixture", []byte(input)) {
			if f.DetectorID == "cohere-api-key" {
				t.Errorf("provider context crossed a record: %q", input)
			}
		}
	}
}

func TestStructuredMultipartVerification(t *testing.T) {
	access := "AKIAIOSFODNN7EXAMPLE"
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	token := strings.Repeat("aB3d", 30) + "="
	var registry []detectors.Detector
	calls := 0
	for _, d := range detectors.DefaultRegistry() {
		if d.Info().ID != "aws-credentials" {
			continue
		}
		aws := d.(detectors.CorrelatedDetector)
		aws.CompositeVerifier = func(_ context.Context, c detectors.Candidate) detectors.VerificationResult {
			calls++
			want := map[string]string{"access_key_id": access, "secret_access_key": secret, "session_token": token}
			if !reflect.DeepEqual(c.SecretParts, want) {
				t.Errorf("verifier received wrong parts: %+v", c.SecretParts)
			}
			return detectors.VerificationResult{Status: detectors.VerificationVerified}
		}
		registry = append(registry, aws)
	}
	input := `{"aws_access_key_id":"AK\u0049AIOSFODNN7EXAMPLE","aws_secret_access_key":"` + strings.Replace(secret, "/", `\u002f`, 1) + `","aws_session_token":"` + token + `"}`
	got := New(Config{Verify: true}, registry).ScanContent(context.Background(), "fixture.json", []byte(input))
	if len(got) != 1 || calls != 1 || !got[0].Verified || got[0].Secret != secret {
		t.Fatalf("decoded multipart verification failed: calls=%d, findings=%+v", calls, got)
	}
	separate := `[{"aws_access_key_id":"AK\u0049AIOSFODNN7EXAMPLE"},{"aws_secret_access_key":"` + strings.Replace(secret, "/", `\u002f`, 1) + `"}]`
	if got := New(Config{}, registry).ScanContent(context.Background(), "separate.json", []byte(separate)); len(got) != 0 {
		t.Fatalf("paired credentials across records: %+v", got)
	}
}

func TestStructuredVerificationSafetyPolicy(t *testing.T) {
	calls := 0
	d := detectors.NewUnsafeRegex("unsafe-test", "Unsafe Test", "high", []string{"unsafe_"}, `\b(unsafe_[A-Za-z0-9]{16})\b`, 1, func(context.Context, string) detectors.VerificationResult {
		calls++
		return detectors.VerificationResult{Status: detectors.VerificationVerified}
	})
	input := []byte(`{"token":"uns\u0061fe_abcdefghijklmnop"}`)
	got := New(Config{Verify: true}, []detectors.Detector{d}).ScanContent(context.Background(), "fixture.json", input)
	if len(got) != 1 || calls != 0 || got[0].Verification.ErrorCategory != "unsafe_verification_disabled" {
		t.Fatalf("policy bypassed: %+v, calls=%d", got, calls)
	}
	got = New(Config{Verify: true, AllowUnsafeVerification: true}, []detectors.Detector{d}).ScanContent(context.Background(), "fixture.json", input)
	if len(got) != 1 || calls != 1 || !got[0].Verified {
		t.Fatalf("opt-in verification failed: %+v, calls=%d", got, calls)
	}
}

func TestStructuredDoesNotAssembleSplitToken(t *testing.T) {
	input := "token: >-\n  ghp_\n  aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD3fG5hJ7\n"
	for _, f := range New(Config{}, detectors.DefaultRegistry()).ScanContent(context.Background(), "fixture.yaml", []byte(input)) {
		if f.DetectorID == "github-token" {
			t.Fatal("folded whitespace was removed to assemble a token")
		}
	}
}

func FuzzStructuredProviderSpans(f *testing.F) {
	var registry []detectors.Detector
	for _, d := range detectors.DefaultRegistry() {
		switch d.Info().ID {
		case "generic-assigned-secret", "github-token", "cohere-api-key", "aws-credentials":
			registry = append(registry, d)
		}
	}
	s := New(Config{}, registry)
	for _, seed := range []string{
		`{"token":"gh\u0070_aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD3fG5hJ7"}`,
		"token: |\n  ghp_aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD3fG5hJ7\n",
		`{"coh\u0065re":{"api_key":"v9K2pQ7mX4rT8nW3b6Y1hJ5kL0sD2fG8"}}`,
		"value: &credential \"ghp_aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD3fG5hJ7\"\ntoken: *credential",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		for _, c := range s.detectCandidates(input) {
			if c.Start < 0 || c.End < c.Start || c.End > len(input) {
				t.Fatalf("invalid span [%d,%d) for %d bytes", c.Start, c.End, len(input))
			}
		}
	})
}
