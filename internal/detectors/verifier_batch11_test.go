package detectors

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var batch11Contracts = []struct {
	id                            string
	verify                        Verifier
	hosts                         []string
	path, header, prefix, success string
	invalid                       []string
}{
	{"intercom-access-token", verifyIntercom, []string{"api.intercom.io", "api.eu.intercom.io", "api.au.intercom.io"}, "/me", "Authorization", "Bearer ", `{"type":"admin","id":"admin-1"}`, []string{`{"type":"user","id":"1"}`, `{"type":"admin","id":1}`}},
	{"launchdarkly-key", verifyLaunchDarkly, []string{"app.launchdarkly.com", "app.eu.launchdarkly.com", "app.launchdarkly.us"}, "/api/v2/caller-identity", "Authorization", "", `{"accountId":"account-1","authKind":"token"}`, []string{`{"accountId":"account-1"}`, `{"accountId":null,"authKind":"token"}`}},
	{"monday-api-token", verifyMonday, []string{"api.monday.com"}, "/v2", "Authorization", "", `{"data":{"me":{"id":"123"}}}`, []string{`{"data":{"other":{"id":"123"}}}`, `{"data":{"me":{"id":false}}}`, `{"data":{"me":null}}`, `{"data":{"me":{"id":"123"}},"errors":[{"message":"permission denied"}]}`}},
	{"atlassian-api-token", verifyAtlassian, []string{"api.atlassian.com"}, "/admin/v1/orgs", "Authorization", "Bearer ", `{"data":[{"id":"org-1","type":"orgs"}]}`, []string{`{"data":null}`, `{"data":[{}]}`, `{"data":[{"id":"org-1","type":"users"}]}`}},
	{"dialpad-api-key", verifyDialpad, []string{"dialpad.com", "sandbox.dialpad.com"}, "/api/v2/company", "Authorization", "Bearer ", `{"id":"123","name":"Company"}`, []string{`{"id":null,"name":"Company"}`, `{"id":[],"name":"Company"}`}},
	{"clockify-api-key", verifyClockify, []string{"api.clockify.me"}, "/api/v1/user", "X-Api-Key", "", `{"id":"user-1","email":"user@example.invalid"}`, []string{`{"id":"user-1"}`, `{"id":"user-1","email":null}`}},
	{"baremetrics-api-key", verifyBaremetrics, []string{"api.baremetrics.com"}, "/v1/account", "Authorization", "Bearer ", `{"account":{"id":"account-1","company":"Company"}}`, []string{`{"id":"account-1","company":"Company"}`, `{"account":{"id":"account-1"}}`}},
	{"webflow-api-key", verifyWebflow, []string{"api.webflow.com"}, "/v2/token/introspect", "Authorization", "Bearer ", `{"authorization":{"id":"auth-1","grantType":"authorization_code"},"application":{"id":"app-1"}}`, []string{`{"id":"user-1","email":"user@example.invalid"}`, `{"authorization":{"id":"auth-1"},"application":{"id":"app-1"}}`}},
	{"vultr-api-key", verifyVultr, []string{"api.vultr.com"}, "/v2/account", "Authorization", "Bearer ", `{"account":{"name":"Company","email":"user@example.invalid"}}`, []string{`{"name":"Company","email":"user@example.invalid"}`, `{"account":{"name":"Company","email":false}}`}},
	{"eventbrite-private-token", verifyEventbrite, []string{"www.eventbriteapi.com"}, "/v3/users/me/", "Authorization", "Bearer ", `{"id":"123","name":"User"}`, []string{`{"id":"123"}`, `{"id":0,"name":"User"}`}},
	{"paystack-secret-key", verifyPaystack, []string{"api.paystack.co"}, "/balance", "Authorization", "Bearer ", `{"status":true,"data":[{"currency":"NGN","balance":0}]}`, []string{`{"status":false,"data":[]}`, `{"status":true,"data":null}`, `{"status":true,"data":[{"currency":"NGN"}]}`, `{"status":true,"data":[{"currency":"NGN","balance":"0"}]}`}},
}

func TestEleventhBatchRequestContractsAndPromotion(t *testing.T) {
	for _, tc := range batch11Contracts {
		t.Run(tc.id, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				method := http.MethodGet
				if tc.id == "monday-api-token" {
					method = http.MethodPost
				}
				if req.Method != method || req.URL.Scheme != "https" || req.URL.Host != tc.hosts[0] || req.URL.Path != tc.path || req.URL.RawQuery != "" || req.Header.Get(tc.header) != tc.prefix+"synthetic-key" || req.Header.Get("Accept") != "application/json" {
					t.Fatalf("unexpected request: %s %s %#v", req.Method, req.URL, req.Header)
				}
				if tc.id == "intercom-access-token" && req.Header.Get("Intercom-Version") != "2.16" {
					t.Fatal("incorrect Intercom version")
				}
				if method == http.MethodPost {
					body, _ := io.ReadAll(req.Body)
					if string(body) != `{"query":"query { me { id } }"}` || req.Header.Get("Content-Type") != "application/json" {
						t.Fatalf("unexpected GraphQL query: %s", body)
					}
				} else if req.Body != nil && req.Body != http.NoBody {
					t.Fatal("GET unexpectedly has a body")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.success))}, nil
			})}
			found := false
			for _, d := range DefaultRegistry() {
				if d.Info().ID != tc.id {
					continue
				}
				found = true
				want := VerificationSafetyReadOnly
				if tc.id == "webflow-api-key" {
					want = VerificationSafetyAuthOnly
				}
				if d.Info().VerificationSafety != want {
					t.Fatalf("safety=%s want=%s", d.Info().VerificationSafety, want)
				}
				c := Candidate{Secret: "synthetic-key", Verifier: d.(RegexDetector).Verifier, VerificationSafety: d.Info().VerificationSafety}
				r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
				if r.Status != VerificationVerified || r.Response != "" || calls != 1 {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
			if !found {
				t.Fatal("missing registry entry")
			}
		})
	}
}

func TestEleventhBatchRejectsAmbiguousResponses(t *testing.T) {
	for _, tc := range batch11Contracts {
		t.Run(tc.id, func(t *testing.T) {
			bodies := append([]string{`{}`, `null`, `[]`, `<html>logged in</html>`, tc.success + " trailing garbage"}, tc.invalid...)
			var p map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.success), &p); err != nil {
				t.Fatal(err)
			}
			p["error"] = json.RawMessage(`"private-metadata"`)
			contradiction, _ := json.Marshal(p)
			bodies = append(bodies, string(contradiction))
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 403, 404, 429, 500, 503} {
				responses := bodies
				if status != 200 {
					responses = append(append([]string(nil), responses...), tc.success, `{"errors":[{"code":"token_revoked","message":"private-metadata"}]}`, `{"code":"invalid_credentials","message":"private-metadata"}`)
				}
				for _, body := range responses {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if calls >= len(tc.hosts) || req.URL.Host != tc.hosts[calls] {
							t.Fatalf("unexpected fallback %s", req.URL)
						}
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
					wantCalls := 1
					if status == 401 || status == 403 {
						wantCalls = len(tc.hosts)
					}
					if r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-metadata") || calls != wantCalls {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestEleventhBatchRegionalFallback(t *testing.T) {
	for _, tc := range batch11Contracts {
		if len(tc.hosts) < 2 {
			continue
		}
		t.Run(tc.id, func(t *testing.T) {
			for target := 1; target < len(tc.hosts); target++ {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if calls >= len(tc.hosts) || req.URL.Host != tc.hosts[calls] {
						t.Fatalf("unexpected host %s", req.URL)
					}
					status, body := 401, `{"message":"different deployment"}`
					if calls == target {
						status, body = 200, tc.success
					}
					calls++
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
				if r.Status != VerificationVerified || r.Response != "" || calls != target+1 {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
		})
	}
}

func TestEleventhBatchTransportFailures(t *testing.T) {
	for _, tc := range batch11Contracts {
		for _, failure := range []error{errors.New("private-metadata"), context.DeadlineExceeded, context.Canceled, nil} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if failure != nil {
					return nil, failure
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: batch10FailingBody{}}, nil
			})}
			r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
			if r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-metadata") || calls != 1 {
				t.Fatalf("%s: calls=%d result=%+v", tc.id, calls, r)
			}
		}
	}
}

func TestEleventhBatchLegitimateEmptyAndNumericValues(t *testing.T) {
	for _, tc := range []struct {
		verify Verifier
		body   string
	}{
		{verifyAtlassian, `{"data":[]}`},
		{verifyPaystack, `{"status":true,"data":[]}`},
		{verifyPaystack, `{"status":true,"data":[{"currency":"USD","balance":-1}]}`},
		{verifyMonday, `{"data":{"me":{"id":123}},"errors":[]}`},
		{verifyDialpad, `{"id":123,"name":"Company"}`},
		{verifyEventbrite, `{"id":123,"name":"User"}`},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key"); r.Status != VerificationVerified || r.Response != "" {
			t.Fatalf("%s: %+v", tc.body, r)
		}
	}
}

func TestEleventhBatchSDKKeyMakesNoRequest(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("SDK key made a REST request")
		return nil, errors.New("unexpected")
	})}
	if r := verifyLaunchDarkly(WithVerificationHTTPClient(context.Background(), client), "sdk-example"); r.Status != VerificationUnsupported {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestEleventhBatchCancellationStopsFallback(t *testing.T) {
	for _, tc := range batch11Contracts {
		if len(tc.hosts) < 2 {
			continue
		}
		t.Run(tc.id, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				cancel()
				return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}
			result := tc.verify(WithVerificationHTTPClient(ctx, client), "synthetic-key")
			if calls != 1 || result.Status != VerificationUnknown || result.ErrorCategory != "cancelled" || result.Response != "" {
				t.Fatalf("calls=%d result=%+v", calls, result)
			}
		})
	}
}
