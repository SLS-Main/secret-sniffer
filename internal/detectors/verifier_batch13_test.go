package detectors

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var batch13Contracts = []struct {
	id                     string
	verify                 Verifier
	endpoint, header, auth string
	valid, invalid         []string
}{
	{"ai21-api-key", verifyAI21, "https://api.ai21.com/studio/v1/library/files?offset=0&limit=1", "Authorization", "Bearer synthetic-key",
		[]string{`[]`, `[{"fileId":"file-1","name":"private-metadata","fileType":"text/plain","status":"error","errorCode":42}]`},
		[]string{`{"files":[]}`, `[null]`, `[{}]`, `[{"fileId":1,"name":"file","fileType":"text/plain","status":"ready"}]`}},
	{"zilliz-api-key", verifyZilliz, "https://api.cloud.zilliz.com/v2/projects", "Authorization", "Bearer synthetic-key",
		[]string{`{"code":0,"data":[]}`, `{"code":0,"data":[{"projectId":"p-1","projectName":"private-metadata"}]}`},
		[]string{`{"data":[]}`, `{"code":null,"data":[]}`, `{"code":"0","data":[]}`, `{"code":0}`, `{"code":0,"data":null}`, `{"code":0,"data":[{}]}`, `{"code":80001,"data":[]}`, `{"code":80002,"data":[]}`, `{"code":21119,"data":[]}`}},
	{"dailyco-api-key", verifyDaily, "https://api.daily.co/v1/", "Authorization", "Bearer synthetic-key",
		[]string{`{"domain_id":"d-1","domain_name":"private-metadata","config":{}}`},
		[]string{`{"total_count":0,"data":[]}`, `{"domain_id":"d-1","domain_name":"domain","config":null}`, `{"domain_id":1,"domain_name":"domain","config":{}}`, `{"error":"forbidden-error"}`}},
	{"hunter-api-key", verifyHunter, "https://api.hunter.io/v2/account", "X-API-KEY", "synthetic-key",
		[]string{`{"data":{"email":"private-metadata","plan_name":"Free"}}`},
		[]string{`{"data":null}`, `{"data":{"email":"user@example.invalid"}}`, `{"data":{"email":false,"plan_name":"Free"}}`}},
	{"koyeb-api-token", verifyKoyeb, "https://app.koyeb.com/v1/account/profile", "Authorization", "Bearer synthetic-key",
		[]string{`{"user":{"id":"u-1","email":"private-metadata"}}`},
		[]string{`{"user":null}`, `{"id":"u-1","email":"user@example.invalid"}`, `{"user":{"id":1,"email":"user@example.invalid"}}`}},
	{"storyblok-access-token", verifyStoryblokAccess, "https://api.storyblok.com/v2/cdn/spaces/me?token=synthetic-key", "Authorization", "",
		[]string{`{"space":{"id":123,"name":"private-metadata"}}`},
		[]string{`{"space":null}`, `{"space":{"id":false,"name":"space"}}`, `{"space":{"id":1}}`}},
}

func TestThirteenthBatchContractsAndAmbiguity(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch13Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d, ok := registry[tc.id]
			if !ok || d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("missing read-only promotion")
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 403, 404, 429, 500, 503} {
				bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
				bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-metadata"}`, `{"errors":[{"message":"private-metadata"}]}`)
				if tc.id != "ai21-api-key" {
					for _, key := range []string{"error", "error_code", "errors"} {
						bodies = append(bodies, strings.TrimSuffix(tc.valid[0], "}")+`,"`+key+`":"private-metadata"}`)
					}
				}
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if calls == 0 && req.URL.String() != tc.endpoint {
							t.Fatalf("endpoint=%s", req.URL)
						}
						calls++
						if req.Method != http.MethodGet || req.Header.Get(tc.header) != tc.auth || req.Header.Get("Accept") != "application/json" || (req.Body != nil && req.Body != http.NoBody) {
							t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					candidate := Candidate{Secret: "synthetic-key", Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}
					r := candidate.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					wantCalls := 1
					if tc.id == "storyblok-access-token" && (status == 401 || status == 403) {
						wantCalls = 5
					}
					if r.Status != want || r.Response != "" || calls != wantCalls || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestThirteenthBatchTransportFailures(t *testing.T) {
	for _, tc := range batch13Contracts {
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
	}
}

func TestThirteenthBatchStoryblokRegions(t *testing.T) {
	hosts := []string{"api.storyblok.com", "api-us.storyblok.com", "api-ca.storyblok.com", "api-ap.storyblok.com", "app.storyblokchina.cn"}
	for target := range hosts {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if calls > target || req.URL.Host != hosts[calls] || req.URL.Scheme != "https" || req.URL.Path != "/v2/cdn/spaces/me" || req.URL.Query().Get("token") != "key+&/?" || len(req.URL.Query()) != 1 {
				t.Fatalf("unexpected regional request: %s", req.URL)
			}
			status, body := 401, `{}`
			if calls == target {
				status, body = 200, `{"space":{"id":1,"name":"space"}}`
			}
			calls++
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		r := verifyStoryblokAccess(WithVerificationHTTPClient(context.Background(), client), "key+&/?")
		if r.Status != VerificationVerified || calls != target+1 || r.Response != "" {
			t.Fatalf("calls=%d result=%+v", calls, r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		cancel()
		return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	r := verifyStoryblokAccess(WithVerificationHTTPClient(ctx, client), "synthetic-key")
	if r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" || calls != 1 {
		t.Fatalf("calls=%d result=%+v", calls, r)
	}
}
