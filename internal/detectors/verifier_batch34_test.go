package detectors

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestThirtyFourthBatchBlockedNoNetwork(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("blocked verifier sent a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range []struct{ id, input, category string }{
		{"cloudflare-ca-key", "v1.0-" + strings.Repeat("A", 171), "credential_type"},
		{"cryptocompare-api-key", "cryptocompare api_key=" + strings.Repeat("A", 64), "verification_context"},
		{"currencyscoop-api-key", "currencyscoop api_key=" + strings.Repeat("a", 32), "credential_type"},
		{"pivotaltracker-api-token", "pivotaltracker token=" + strings.Repeat("A", 32), "verification_context"},
		{"interseller-api-key", "interseller key=" + batch30UUID, "verification_context"},
		{"autopilot-api-key", "autopilot key=" + strings.Repeat("a", 32), "verification_context"},
		{"wit-ai-token", "wit.ai token=" + strings.Repeat("A", 32), "verification_context"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c := batch30Candidate(t, registry[tc.id], tc.input)
			if registry[tc.id].Info().VerificationSafety != VerificationSafetyUnreviewed {
				t.Fatalf("unexpected safety: %+v", c)
			}
			for _, policy := range []VerificationPolicy{{}, {AllowUnsafe: true}, {AllowUnreviewed: true}, {AllowUnreviewed: true, AllowUnsafe: true}} {
				r := c.VerifyWithPolicy(ctx, policy)
				want, category := VerificationNotAttempted, "unreviewed_verification_disabled"
				if policy.AllowUnreviewed {
					want, category = VerificationUnknown, tc.category
				}
				if r.Status != want || r.ErrorCategory != category || r.Response != "" || strings.Contains(r.Message, c.Secret) {
					t.Fatalf("%+v", r)
				}
			}
			// Call the hook directly as well: the no-network guarantee must
			// survive bypassing the policy wrapper and arbitrary supplied context.
			c.SecretParts = map[string]string{"endpoint": "https://other.invalid", "credential_type": "bearer"}
			if r := registry[tc.id].(RegexDetector).Verifier(ctx, c.Secret); r.Status != VerificationUnknown || r.Response != "" {
				t.Fatalf("%+v", r)
			}
			if r := c.VerifyWithPolicy(ctx, VerificationPolicy{AllowUnreviewed: true}); r.Status != VerificationUnknown {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestThirtyFourthBatchMoonClerkContract(t *testing.T) {
	c := batch30Candidate(t, batch30Registry()["moonclerk-api-key"], "moonclerk api_key="+strings.Repeat("a", 32))
	if c.VerificationSafety != VerificationSafetyReadOnly {
		t.Fatalf("%+v", c)
	}
	valid := []string{`{"forms":[]}`, `{"forms":[{"id":1,"title":"private-data"}]}`, `{"forms":[{"id":1,"title":"private-data","access_token":"private-token","currency":"USD","payment_volume":0,"successful_checkout_count":0}],"next":"https://other.invalid"}`}
	bodies := append(append([]string{}, valid...), `{}`, `null`, `[]`, `{"forms":null}`, `{"forms":[{}]}`, `{"forms":[{"id":"1","title":"form"}]}`, `{"forms":[{"id":0,"title":"form"}]}`, `{"forms":[{"id":1,"title":null}]}`, `{"forms":[{"id":1,"title":"form","error":"denied"}]}`, `{"forms":[],"errors":["denied"]}`, `{"forms":[],"error_code":401}`, `<html>Login</html>`, valid[0]+" trailing")
	for _, status := range []int{200, 201, 204, 301, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
		for i, body := range bodies {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.URL.String() != "https://api.moonclerk.com/forms?count=1&offset=0" || req.Body != nil || req.Header.Get("Authorization") != "Token token="+c.Secret || req.Header.Get("Accept") != "application/vnd.moonclerk+json;version=1" {
					t.Fatalf("unexpected request %s %s", req.Method, req.URL)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
			want := VerificationUnknown
			if status == 200 && i < len(valid) {
				want = VerificationVerified
			}
			if calls != 1 || r.Status != want || r.Response != "" || strings.Contains(r.Message, "private-") {
				t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
			}
		}
	}
	for _, mode := range []string{"network", "read", "oversize", "cancel", "timeout"} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			switch mode {
			case "network":
				return nil, errors.New("private-token")
			case "read":
				return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
			case "cancel":
				return nil, context.Canceled
			case "timeout":
				return nil, context.DeadlineExceeded
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(valid[0] + strings.Repeat(" ", maxVerificationResponseBytes)))}, nil
		})}
		r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
		if calls != 1 || r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-token") {
			t.Fatalf("%s: %+v calls=%d", mode, r, calls)
		}
	}
}
