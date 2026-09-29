package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"secret-sniffer/internal/detectors"
)

type regressionTransport func(*http.Request) (*http.Response, error)

func (f regressionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func regressionRegistry(id string) []detectors.Detector {
	for _, d := range detectors.DefaultRegistry() {
		if d.Info().ID == id {
			return []detectors.Detector{d}
		}
	}
	panic("missing detector: " + id)
}

func TestContextCredentialsHaveIndependentVerification(t *testing.T) {
	ds := regressionRegistry("autoklose-api-key")
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	calls := 0
	ctx := detectors.WithVerificationHTTPClient(context.Background(), &http.Client{Transport: regressionTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		code, body := 200, `{"id":1,"email":"a@example.com","role":"user"}`
		if r.URL.Query().Get("api_token") == b {
			code, body = 401, `{"error":"invalid"}`
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	s := New(Config{Verify: true}, ds)
	for _, key := range []string{a, b, a} {
		fs := s.ScanContent(ctx, "input.env", []byte("AUTOKLOSE_API_KEY="+key))
		if len(fs) != 1 {
			t.Fatalf("findings=%d", len(fs))
		}
		if fs[0].Verified != (key == a) {
			t.Fatalf("wrong verification for credential: %+v", fs[0].Verification)
		}
	}
	if calls != 2 {
		t.Fatalf("requests=%d, want 2", calls)
	}
}

func TestInvalidStructuredEndpointsNeverVerify(t *testing.T) {
	key := strings.Repeat("A", 40)
	inputs := map[string]string{
		"empty JSON":       fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"STORMBOARD_API_URL":""}`, key),
		"null JSON":        fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"STORMBOARD_API_URL":null}`, key),
		"boolean JSON":     fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"STORMBOARD_API_URL":false}`, key),
		"object JSON":      fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"STORMBOARD_API_URL":{}}`, key),
		"array JSON":       fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"STORMBOARD_API_URL":[]}`, key),
		"empty env":        "STORMBOARD_API_KEY=" + key + "\nSTORMBOARD_API_URL=\n",
		"newline JSON":     fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"STORMBOARD_API_URL":"https://untrusted.\ninvalid"}`, key),
		"distant JSON":     fmt.Sprintf(`{"STORMBOARD_API_KEY":%q,"padding":%q,"STORMBOARD_API_URL":"https://untrusted.invalid"}`, key, strings.Repeat("x", 600)),
		"null YAML":        "STORMBOARD_API_KEY: " + key + "\nSTORMBOARD_API_URL: null\n",
		"object YAML":      "STORMBOARD_API_KEY: " + key + "\nSTORMBOARD_API_URL: {}\n",
		"nested flow YAML": "service: {STORMBOARD_API_KEY: " + key + ", STORMBOARD_API_URL: https://untrusted.invalid}\n",
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			calls := 0
			ctx := detectors.WithVerificationHTTPClient(context.Background(), &http.Client{Transport: regressionTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":200,"message":"Connected, w00t"}`))}, nil
			})})
			fs := New(Config{Verify: true}, regressionRegistry("stormboard-api-key")).ScanContent(ctx, "input", []byte(input))
			if calls != 0 || len(fs) != 1 {
				t.Fatalf("requests=%d findings=%d", calls, len(fs))
			}
			if fs[0].Verification.Status != detectors.VerificationUnknown {
				t.Fatalf("verification=%+v", fs[0].Verification)
			}
		})
	}
}
