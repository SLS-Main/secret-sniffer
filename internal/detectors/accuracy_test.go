package detectors

import (
	"strings"
	"testing"
)

func TestAssignedCompleteValues(t *testing.T) {
	d := AssignedSecretDetector{}
	for _, input := range []string{
		`password="v9K2pQ7mX4rT8nW3!tail"`,
		`{"password":"v9K2pQ7mX4rT8nW3!tail"}`,
		`api-key=v9K2pQ7mX4rT8nW3!tail`,
	} {
		got := d.Detect([]byte(input))
		if len(got) != 1 || got[0].Secret != "v9K2pQ7mX4rT8nW3!tail" {
			t.Fatalf("%q: %+v", input, got)
		}
		if input[got[0].Start:got[0].End] != got[0].Secret {
			t.Fatal("incorrect value offsets")
		}
	}
	for _, input := range []string{
		"password:\n  nested-configuration-key: value",
		`password="unterminated-secret-value`,
		`password = generatePasswordForUser ()`,
		`not-password=not-a-real-secret-value`,
	} {
		if got := d.Detect([]byte(input)); len(got) != 0 {
			t.Errorf("unexpected literal from %q: %+v", input, got)
		}
	}
}

func TestContextualTokenCompleteness(t *testing.T) {
	for _, d := range DefaultRegistry() {
		if d.Info().ID != "cohere-api-key" {
			continue
		}
		valid := strings.Repeat("aB3d", 64)
		if got := d.Detect([]byte("cohere api_key=" + valid)); len(got) != 1 || got[0].Secret != valid {
			t.Fatal("complete supported token lost")
		}
		if got := d.Detect([]byte("cohere api_key=" + valid + "Z")); len(got) != 0 {
			t.Fatal("truncated oversized token")
		}
		for _, context := range []string{
			"cohere\n--- # next document\napi_key=",
			"cohere\n...\napi_key=",
			"cohere\n[other]\napi_key=",
			"{provider: cohere}, {api_key=",
			"{cohere: {}}, {api_key=",
			"cohere:\n  enabled: true\nother:\n  api_key=",
		} {
			if got := d.Detect([]byte(context + valid)); len(got) != 0 {
				t.Errorf("provider context leaked: %q", context)
			}
		}
	}
}

func TestGoogleClientSecretEvidence(t *testing.T) {
	modern := "GOCSPX-" + strings.Repeat("aB3d", 7)
	if !registryFinds("google-oauth-client-secret", modern, modern) {
		t.Fatal("modern Google signature lost")
	}
	for _, d := range DefaultRegistry() {
		if d.Info().ID != "google-oauth-client-secret" {
			continue
		}
		for _, input := range []string{modern + "Z", "client_secret=" + strings.Repeat("aB3d", 6), "google\n---\nclient_secret=" + strings.Repeat("aB3d", 6)} {
			if got := d.Detect([]byte(input)); len(got) != 0 {
				t.Errorf("unsupported Google attribution: %q", input)
			}
		}
	}
}
