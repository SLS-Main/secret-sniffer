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

var batch12Contracts = []struct {
	id                  string
	verify              Verifier
	hosts               []string
	path, query, prefix string
	valid, invalid      []string
}{
	{"contentful-pat", verifyContentful, []string{"api.contentful.com", "api.eu.contentful.com"}, "/spaces", "limit=1", "Bearer ",
		[]string{`{"sys":{"type":"Array"},"items":[]}`, `{"sys":{"type":"Array"},"items":[{"sys":{"type":"Space","id":"space-1"},"name":"private-metadata"}]}`},
		[]string{`{"items":[]}`, `{"sys":{"type":"Error"},"items":[]}`, `{"sys":{"type":"Array"},"items":null}`, `{"sys":{"type":"Array"},"items":[{"sys":{"type":"Entry","id":"1"},"name":"space"}]}`}},
	{"assemblyai-api-key", verifyAssemblyAI, []string{"api.assemblyai.com", "api.eu.assemblyai.com"}, "/v2/transcript", "limit=1", "",
		[]string{`{"page_details":{"result_count":0},"transcripts":[]}`, `{"page_details":{"result_count":1},"transcripts":[{"id":"id-1","status":"error","error":"private-metadata"}]}`},
		[]string{`{"transcripts":[]}`, `{"page_details":{"result_count":1},"transcripts":[]}`, `{"page_details":{"result_count":0},"transcripts":null}`, `{"page_details":{"result_count":1},"transcripts":[{"id":"id-1","status":"invalid"}]}`}},
	{"storyblok-personal-access-token", verifyStoryblokPersonal, []string{"mapi.storyblok.com", "api-us.storyblok.com", "api-ca.storyblok.com", "api-ap.storyblok.com", "app.storyblokchina.cn"}, "/v1/spaces", "per_page=1", "",
		[]string{`{"spaces":[]}`, `{"spaces":[{"id":123,"name":"private-metadata"}]}`},
		[]string{`{"spaces":null}`, `{"spaces":[{}]}`, `{"spaces":[{"id":false,"name":"space"}]}`}},
	{"cloudconvert-api-key", verifyCloudConvert, []string{"api.cloudconvert.com"}, "/v2/users/me", "", "Bearer ",
		[]string{`{"data":{"id":1,"username":"private-metadata","email":"user@example.invalid"}}`, `{"data":{"id":"1","username":"user","email":"user@example.invalid"}}`},
		[]string{`{"data":{"id":1,"username":"user"}}`, `{"data":null}`, `{"id":1,"username":"user","email":"user@example.invalid"}`}},
	{"smartsheet-access-token", verifySmartsheet, []string{"api.smartsheet.com", "api.smartsheet.eu", "api.smartsheet.au"}, "/2.0/users/me", "", "Bearer ",
		[]string{`{"id":48569348493401200,"email":"private-metadata"}`},
		[]string{`{"id":1}`, `{"id":1,"email":"user@example.invalid","errorCode":1004}`, `{"id":null,"email":"user@example.invalid"}`}},
	{"rev-ai-api-key", verifyRevAI, []string{"api.rev.ai"}, "/speechtotext/v1/account", "", "Bearer ",
		[]string{`{"email":"private-metadata","free_balance":0,"purchased_balance":0,"total_balance":0}`, `{"email":"user@example.invalid","free_balance":5.5,"purchased_balance":8.5,"total_balance":14}`},
		[]string{`{"email":"user@example.invalid"}`, `{"email":"user@example.invalid","free_balance":null,"purchased_balance":0,"total_balance":0}`, `{"email":"user@example.invalid","free_balance":"0","purchased_balance":0,"total_balance":0}`}},
	{"mailerlite-api-key", verifyMailerLite, []string{"connect.mailerlite.com"}, "/api/groups", "limit=1", "Bearer ",
		[]string{`{"data":[]}`, `{"data":[{"id":"1","name":"private-metadata"}],"links":{"next":"https://other.invalid/"}}`},
		[]string{`{"data":null}`, `{"data":[{"id":1,"name":"group"}]}`, `{"data":[{"id":"1"}]}`, `{"data":[{"id":"UTC","name":"UTC"}],"error":"unauthorized"}`}},
	{"capsulecrm-api-key", verifyCapsuleCRM, []string{"api.capsulecrm.com"}, "/api/v2/users/current", "", "Bearer ",
		[]string{`{"user":{"id":1,"username":"private-metadata"}}`},
		[]string{`{"user":null}`, `{"user":{"id":0,"username":"user"}}`, `{"id":1,"username":"user"}`}},
}

func TestTwelfthBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, detector := range DefaultRegistry() {
		if d, ok := detector.(RegexDetector); ok {
			registry[d.Info().ID] = d
		}
	}
	for _, tc := range batch12Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d, ok := registry[tc.id]
			if !ok || d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("missing read-only promotion")
			}
			for target := range tc.hosts {
				for _, body := range tc.valid {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if calls > target || req.URL.Host != tc.hosts[calls] || req.URL.Path != tc.path || req.URL.RawQuery != tc.query || req.Method != http.MethodGet || req.URL.Scheme != "https" || req.Header.Get("Authorization") != tc.prefix+"synthetic-key" || req.Header.Get("Accept") != "application/json" || (req.Body != nil && req.Body != http.NoBody) {
							t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
						}
						if tc.id == "contentful-pat" && req.Header.Get("Content-Type") != "application/vnd.contentful.management.v1+json" {
							t.Fatal("missing management version")
						}
						status, response := 401, `{"error":"different deployment"}`
						if calls == target {
							status, response = 200, body
						}
						calls++
						return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
					})}
					candidate := Candidate{Secret: "synthetic-key", Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}
					r := candidate.Verify(WithVerificationHTTPClient(context.Background(), client))
					if r.Status != VerificationVerified || r.Response != "" || strings.Contains(r.Message, "private-metadata") || calls != target+1 {
						t.Fatalf("calls=%d result=%+v", calls, r)
					}
				}
			}
		})
	}
}

func TestTwelfthBatchAmbiguity(t *testing.T) {
	for _, tc := range batch12Contracts {
		t.Run(tc.id, func(t *testing.T) {
			bodies := append([]string{`{}`, `null`, `[]`, `<html>OK</html>`, tc.valid[0] + " trailing", `{"error":"AccessDenied user.read scope"}`}, tc.invalid...)
			for _, field := range []string{"error", "error_code", "errors"} {
				var p map[string]json.RawMessage
				if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
					t.Fatal(err)
				}
				p[field] = json.RawMessage(`"private-metadata"`)
				b, _ := json.Marshal(p)
				bodies = append(bodies, string(b))
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 403, 404, 429, 500, 503} {
				responses := bodies
				if status != 200 {
					responses = append(append([]string(nil), bodies...), tc.valid...)
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
					if r.Status != VerificationUnknown || r.Response != "" || calls != wantCalls || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestTwelfthBatchTransportAndCancellation(t *testing.T) {
	for _, tc := range batch12Contracts {
		for _, failure := range []error{errors.New("private-metadata"), context.Canceled, context.DeadlineExceeded, nil} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if failure != nil {
					return nil, failure
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: batch10FailingBody{}}, nil
			})}
			r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
			if r.Status != VerificationUnknown || r.Response != "" || calls != 1 || strings.Contains(r.Message, "private-metadata") {
				t.Fatalf("%s: calls=%d result=%+v", tc.id, calls, r)
			}
		}
		if len(tc.hosts) < 2 {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			cancel()
			return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})}
		r := tc.verify(WithVerificationHTTPClient(ctx, client), "synthetic-key")
		cancel()
		if r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" || calls != 1 {
			t.Fatalf("%s: calls=%d result=%+v", tc.id, calls, r)
		}
	}
}
