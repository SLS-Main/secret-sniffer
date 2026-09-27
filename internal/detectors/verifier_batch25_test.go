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

var batch25Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	header, prefix string
	valid, invalid []string
}{
	{"bitbar-api-key", verifyBitBar, []string{"https://cloud.bitbar.com/api/me"}, "Authorization", "Basic c2VjcmV0Og==",
		[]string{`{"id":1,"email":"mail","enabled":false,"apiKey":"private-metadata"}`},
		[]string{`{"id":"1","email":"mail"}`, `{"id":null,"email":"mail"}`, `{"id":1}`}},
	{"blazemeter-api-key", verifyBlazeMeter, []string{"https://api.runscope.com/account"}, "Authorization", "Bearer ",
		[]string{`{"data":{"uuid":"id","name":"name","teams":[]},"meta":{"status":"success"}}`},
		[]string{`{"data":{},"meta":{"status":"success"}}`, `{"data":{"uuid":"id","name":"name"},"meta":{"status":"error"}}`, `{"data":{"uuid":"id","name":"name","error":"denied"},"meta":{"status":"success"}}`}},
	{"pendo-integration-key", verifyPendo, []string{"https://app.pendo.io/api/v1/metadata/schema/account", "https://app.eu.pendo.io/api/v1/metadata/schema/account", "https://us1.app.pendo.io/api/v1/metadata/schema/account", "https://app.jpn.pendo.io/api/v1/metadata/schema/account", "https://app.au.pendo.io/api/v1/metadata/schema/account"}, "x-pendo-integration-key", "",
		[]string{`{"auto":{},"agent":{},"custom":{}}`, `{"auto":{"id":{"Type":"string"}},"hubspot":{"list":{"Type":"","sample":["private-metadata"]}}}`},
		[]string{`{"auto":null}`, `{"auto":[]}`, `{"auto":{"id":{"Type":null}}}`, `{"auto":{"id":{}}}`, `{"auto":{},"agent":{"email":{"Type":"string","error":"denied"}}}`}},
	{"smartrecruiters-api-key", verifySmartRecruiters, []string{"https://api.smartrecruiters.com/user-api/v201804/users/me", "https://api.smartrecruiters.com/user-api/v201804/users/me"}, "X-SmartToken", "",
		[]string{`{"id":"id","firstName":"first","lastName":"last","systemRole":{"id":"ADMINISTRATOR"},"active":false}`},
		[]string{`{"id":"id","firstName":"first","lastName":"last"}`, `{"id":1,"firstName":"first","lastName":"last","systemRole":{"id":"ADMINISTRATOR"}}`, `{"id":"id","firstName":"first","lastName":"last","systemRole":{"id":"ADMINISTRATOR","error":"denied"}}`}},
	{"alconost-api-key", verifyAlconost, []string{"https://api.nitrotranslate.com/v1/account"}, "Authorization", "Basic c2VjcmV0Og==",
		[]string{`{"id":1,"balance":0,"reserved":0}`, `{"id":"123","balance":-1.25,"reserved":4.5,"balance_overdraft_allowed":true}`},
		[]string{`{"id":1}`, `{"id":null,"balance":0,"reserved":0}`, `{"id":"name","balance":0,"reserved":0}`, `{"id":1,"balance":"0","reserved":0}`, `{"id":1,"balance":0,"reserved":null}`}},
	{"airbrake-user-key", verifyAirbrakeUser, []string{"https://api.airbrake.io/api/v4/projects?limit=1&key=secret"}, "", "",
		[]string{`{"projects":[]}`, `{"projects":[{"id":1,"name":"name","deployId":null}]}`},
		[]string{`{"projects":null}`, `{"projects":[{"id":"1","name":"name"}]}`, `{"projects":[],"code":401}`, `{"projects":[{}]}`}},
	{"sslmate-api-key", verifySSLMate, []string{"https://sslmate.com/api/v2/certs/example.com", "https://sandbox.sslmate.com/api/v2/certs/example.com"}, "Authorization", "Basic c2VjcmV0Og==",
		[]string{`{"exists":false,"cn":"example.com","type":null}`, `{"exists":true,"cn":"example.com","current_download":"private-metadata"}`},
		[]string{`{"exists":false}`, `{"exists":null,"cn":"example.com"}`, `{"exists":"true","cn":"example.com"}`, `{"exists":true,"cn":"other.invalid"}`, `{"exists":false,"cn":"example.com","reason":"bad_credentials"}`}},
	{"surveysparrow-api-key", verifySurveySparrow, []string{"https://api.surveysparrow.com/v3/roles?limit=1&page=1", "https://eu-api.surveysparrow.com/v3/roles?limit=1&page=1", "https://ap-api.surveysparrow.com/v3/roles?limit=1&page=1", "https://me-api.surveysparrow.com/v3/roles?limit=1&page=1", "https://eu-ln-api.surveysparrow.com/v3/roles?limit=1&page=1", "https://ap-sy-app.surveysparrow.com/v3/roles?limit=1&page=1", "https://ca-api.surveysparrow.com/v3/roles?limit=1&page=1"}, "Authorization", "Bearer ",
		[]string{`{"data":[],"has_next_page":false}`, `{"data":[{"id":1,"name":"ACCOUNT_OWNER","deleted_at":null}],"has_next_page":true}`},
		[]string{`{"data":[],"has_next_page":null}`, `{"data":null,"has_next_page":false}`, `{"data":[{"id":"1","name":"name"}],"has_next_page":false}`}},
	{"protocolsio-api-token", verifyProtocolsIO, []string{"https://www.protocols.io/api/v3/session/profile"}, "Authorization", "Bearer ",
		[]string{`{"status_code":0,"user":{"username":"user","email":"mail","name":"","bio":null},"warning_code":1}`},
		[]string{`{"user":{"username":"user","email":"mail"}}`, `{"status_code":null,"user":{"username":"user","email":"mail"}}`, `{"status_code":1218}`, `{"status_code":1219}`, `{"status_code":0,"user":{"id":1}}`, `{"status_code":0,"user":{"username":"user","email":"mail","error":"denied"}}`}},
	{"virustotal-api-key", verifyVirusTotal, []string{"https://www.virustotal.com/api/v3/files/" + strings.Repeat("0", 64)}, "x-apikey", "",
		[]string{`{"data":{"type":"file","id":"` + strings.Repeat("0", 64) + `","attributes":{}}}`},
		[]string{`{"data":{"type":"file","id":"other","attributes":{}}}`, `{"data":{"type":"user","id":"` + strings.Repeat("0", 64) + `","attributes":{}}}`, `{"data":{"type":"file","id":"` + strings.Repeat("0", 64) + `","attributes":null}}`}},
}

func checkBatch25Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch25Contracts[index]
	if call >= len(tc.urls) || req.Method != http.MethodGet || req.URL.String() != tc.urls[call] || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	header, value := tc.header, tc.prefix+"secret"
	if strings.HasPrefix(tc.prefix, "Basic ") {
		value = tc.prefix
	}
	if tc.id == "smartrecruiters-api-key" && call == 1 {
		header, value = "Authorization", "Bearer secret"
		if req.Header.Get("X-SmartToken") != "" {
			t.Fatal("mixed credential headers")
		}
	}
	if header != "" && req.Header.Get(header) != value {
		t.Fatalf("unexpected %s header", header)
	}
}

func TestTwentyFifthBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[d.Info().ID] = r
		}
	}
	if len(batch25Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	for index, tc := range batch25Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			if d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `[]`, `<html>OK</html>`, tc.valid[0]+" trailing")
			for _, field := range []string{"error", "errors", "error_code"} {
				var p map[string]json.RawMessage
				if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
					t.Fatal(err)
				}
				p[field] = json.RawMessage(`"private-metadata"`)
				b, _ := json.Marshal(p)
				bodies = append(bodies, string(b))
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch25Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: "secret", Verifier: d.Verifier, VerificationSafety: VerificationSafetyReadOnly}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want, wantCalls := VerificationUnknown, 1
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if status == 401 || status == 403 {
						wantCalls = len(tc.urls)
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestTwentyFifthBatchFallbackAndFailures(t *testing.T) {
	for index, tc := range batch25Contracts {
		t.Run(tc.id, func(t *testing.T) {
			for _, failure := range []error{errors.New("private-metadata"), context.Canceled, context.DeadlineExceeded, nil} {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if failure != nil {
						return nil, failure
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: batch10FailingBody{}}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "secret")
				if calls != 1 || r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
			if len(tc.urls) < 2 {
				return
			}
			for _, status := range []int{401, 403} {
				for _, cancelled := range []bool{false, true} {
					ctx, cancel := context.WithCancel(context.Background())
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch25Request(t, index, calls, req)
						calls++
						code, body := status, `{"error":"denied"}`
						if calls == len(tc.urls) {
							code, body = 200, tc.valid[0]
						}
						if cancelled {
							cancel()
						}
						return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := tc.verify(WithVerificationHTTPClient(ctx, client), "secret")
					cancel()
					if cancelled {
						if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
							t.Fatalf("calls=%d result=%+v", calls, r)
						}
					} else if calls != len(tc.urls) || r.Status != VerificationVerified || r.Response != "" {
						t.Fatalf("calls=%d result=%+v", calls, r)
					}
				}
			}
		})
	}
}

func TestTwentyFifthBatchVirusTotalStructuredErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   VerificationStatus
	}{
		{404, `{"error":{"code":"NotFoundError","message":"private-metadata"}}`, VerificationVerified},
		{401, `{"error":{"code":"WrongCredentialsError","message":"private-metadata"}}`, VerificationUnverified},
		{404, `{"error":{"code":"ForbiddenError","message":"NotFoundError"}}`, VerificationUnknown},
		{401, `{"error":{"code":"UserNotActiveError","message":"WrongCredentialsError"}}`, VerificationUnknown},
		{404, `{"message":"NotFoundError"}`, VerificationUnknown},
		{404, `{"error":{"code":"NotFoundError"},"data":{}}`, VerificationUnknown},
		{404, `{"error":{"code":"NotFoundError","errors":["denied"]}}`, VerificationUnknown},
		{200, `{"error":{"code":"NotFoundError"}}`, VerificationUnknown},
		{429, `{"error":{"code":"WrongCredentialsError"}}`, VerificationUnknown},
		{503, `{"error":{"code":"NotFoundError"}}`, VerificationUnknown},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		r := verifyVirusTotal(WithVerificationHTTPClient(context.Background(), client), "secret")
		if r.Status != tc.want || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
			t.Fatalf("status=%d body=%s result=%+v", tc.status, tc.body, r)
		}
	}
}

func TestTwentyFifthBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := []string{"bitbar api_key", "blazemeter api_key", "pendo integration_key", "smartrecruiters token", "alconost api_key", "airbrake user_key", "sslmate api_key", "survey_sparrow token", "protocols.io token", "virustotal api_key"}
	secrets := []string{strings.Repeat("A", 32), "12345678-1234-1234-1234-123456789abc", strings.Repeat("A", 31) + "-", strings.Repeat("A", 31) + "-", strings.Repeat("A", 32), strings.Repeat("a", 40), strings.Repeat("A", 31) + "-", strings.Repeat("A", 87) + "-", strings.Repeat("A", 31) + "-", strings.Repeat("a", 64)}
	for i, tc := range batch25Contracts {
		got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `"`))
		if len(got) != 1 || got[0].Secret != secrets[i] {
			t.Fatalf("%s lost token: %+v", tc.id, got)
		}
		if got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `+suffix"`)); len(got) != 0 {
			t.Fatalf("%s truncated token", tc.id)
		}
	}
}

func TestTwentyFifthBatchPendoResponseCap(t *testing.T) {
	body := `{"auto":{"id":{"Type":"string","sample":"` + strings.Repeat("A", maxVerificationResponseBytes) + `"}}}`
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	if r := verifyPendo(WithVerificationHTTPClient(context.Background(), client), "secret"); calls != 1 || r.Status != VerificationUnknown || r.Response != "" {
		t.Fatalf("calls=%d result=%+v", calls, r)
	}
}
