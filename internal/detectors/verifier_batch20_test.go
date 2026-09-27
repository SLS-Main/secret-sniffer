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

var batch20Contracts = []struct {
	id, url, header, prefix, secret string
	verify                          Verifier
	valid, invalid                  []string
}{
	{"figma-pat", "https://api.figma.com/v1/me", "X-Figma-Token", "", "figd_" + strings.Repeat("A", 40), verifyFigma,
		[]string{`{"id":"1","email":"private-metadata","handle":"name","img_url":null}`},
		[]string{`{"id":"1"}`, `{"id":1,"email":"mail","handle":"name"}`, `{"status":403,"err":"Invalid scope"}`, `{"err":"Invalid token"}`, `{"id":"1","email":"mail","handle":"name","err":"Invalid scope"}`}},
	{"clerk-secret-key", "https://api.clerk.com/v1/users/count", "Authorization", "Bearer ", "sk_test_" + strings.Repeat("A", 32), verifyClerk,
		[]string{`{"object":"total_count","total_count":0}`, `{"object":"total_count","total_count":12}`},
		[]string{`{"total_count":12}`, `{"object":"user","total_count":12}`, `{"object":"total_count","total_count":null}`, `{"object":"total_count","total_count":"12"}`, `{"object":"total_count","total_count":-1}`, `{"errors":[{"code":"clerk_key_invalid"}]}`}},
	{"zeplin-token", "https://api.zeplin.dev/v1/users/me", "Authorization", "Bearer ", strings.Repeat("A", 40), verifyZeplin,
		[]string{`{"id":"user1","username":"name","email":"alias@user.zeplin.io"}`, `{"id":"user1","username":"name","email":"private-metadata","avatar":null}`},
		[]string{`{"id":"user1"}`, `{"id":"user1","username":null,"email":"alias"}`}},
	{"adafruit-io-key", "https://io.adafruit.com/api/v2/user", "X-AIO-Key", "", "aio_" + strings.Repeat("A", 32), verifyAdafruitIO,
		[]string{`{"id":1,"username":"private-metadata","created_at":"date","name":null}`},
		[]string{`{"id":"1","username":"user","created_at":"date"}`, `{"id":0,"username":"user","created_at":"date"}`, `{"id":1,"username":null,"created_at":"date"}`}},
	{"pipedream-api-key", "https://api.pipedream.com/v1/users/me", "Authorization", "Bearer ", strings.Repeat("A", 32), verifyPipedream,
		[]string{`{"data":{"id":"u_1","username":"user","email":"private-metadata","orgs":[]}}`, `{"data":{"id":"u_1","username":"user","email":"mail","billing_period_credits":0}}`},
		[]string{`{"data":[]}`, `{"data":{"id":"u_1"}}`, `{"data":{"id":"u_1","username":"user","email":"mail","error":"denied"}}`}},
	{"line-messaging-token", "https://api.line.me/v2/bot/info", "Authorization", "Bearer ", strings.Repeat("A", 171) + "=", verifyLINEMessaging,
		[]string{`{"userId":"U1","basicId":"@1","displayName":"private-metadata","chatMode":"bot","markAsReadMode":"auto"}`, `{"userId":"U1","basicId":"@1","displayName":"name","chatMode":"chat","markAsReadMode":"manual"}`},
		[]string{`{"userId":"U1"}`, `{"userId":"U1","basicId":"@1","displayName":"name","chatMode":"other","markAsReadMode":"auto"}`, `{"userId":"U1","basicId":"@1","displayName":"name","chatMode":"bot","markAsReadMode":null}`}},
	{"bannerbear-api-key", "https://api.bannerbear.com/v2/account", "Authorization", "Bearer ", strings.Repeat("A", 32), verifyBannerbear,
		[]string{`{"uid":"acct1","created_at":"date","api_usage":0,"api_quota":0,"paid_plan_name":null,"current_project":null}`, `{"uid":"acct1","created_at":"date","api_usage":101,"api_quota":100}`},
		[]string{`{"uid":"acct1"}`, `{"uid":"acct1","created_at":"date","api_usage":null,"api_quota":100}`, `{"uid":"acct1","created_at":"date","api_usage":"0","api_quota":100}`}},
	{"elastic-email-api-key", "https://api.elasticemail.com/v4/lists?limit=1&offset=0", "X-ElasticEmail-ApiKey", "", strings.Repeat("A", 96), verifyElasticEmail,
		[]string{`[]`, `[{"ListName":"private-metadata","DateAdded":"date","AllowUnsubscribe":false,"PublicListID":null}]`},
		[]string{`[{}]`, `[null]`, `[{"ListName":"name","DateAdded":"date","AllowUnsubscribe":null}]`, `[{"ListName":"name","DateAdded":"date","AllowUnsubscribe":"false"}]`, `[{"ListName":"name","DateAdded":"date","AllowUnsubscribe":true,"error":"denied"}]`}},
	{"tradier-token", "https://api.tradier.com/v1/user/profile", "Authorization", "Bearer ", strings.Repeat("A", 32), verifyTradier,
		[]string{`{"profile":{"id":"id-1","name":"private-metadata","account":[]}}`, `{"profile":{"id":"id-1","name":"name","account":{"status":"closed"}}}`},
		[]string{`{"profile":{}}`, `{"profile":{"id":"id-1","name":null}}`, `{"profile":{"id":"id-1","name":"name","errors":["denied"]}}`}},
	{"triggerdev-api-key", "https://api.trigger.dev/api/v1/runs?page%5Bsize%5D=10", "Authorization", "Bearer ", "tr_prod_sk_" + strings.Repeat("A", 32), verifyTriggerDev,
		[]string{`{"data":[],"pagination":{}}`, `{"data":[{"id":"run_1","status":"FAILED","taskIdentifier":"private-metadata","createdAt":"date","updatedAt":"date","isTest":false,"env":{"id":"env1","name":"dev"}}],"pagination":{"next":"run_2"}}`},
		[]string{`{"data":[]}`, `{"data":null,"pagination":{}}`, `{"data":[],"pagination":{"next":12}}`, `{"data":[{}],"pagination":{}}`, `{"data":[{"id":"run_1","status":"COMPLETED","taskIdentifier":"task","createdAt":"date","updatedAt":"date","isTest":null,"env":{"id":"env1","name":"dev"}}],"pagination":{}}`}},
}

func TestTwentiethBatchContracts(t *testing.T) {
	if len(batch20Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch20Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			if d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("wrong runtime safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing")
			if tc.id != "elastic-email-api-key" {
				for _, field := range []string{"error", "errors", "error_code"} {
					var p map[string]json.RawMessage
					if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
						t.Fatal(err)
					}
					p[field] = json.RawMessage(`"private-metadata"`)
					body, _ := json.Marshal(p)
					bodies = append(bodies, string(body))
				}
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						wantURL := tc.url
						if calls == 1 && tc.id == "tradier-token" {
							wantURL = "https://sandbox.tradier.com/v1/user/profile"
						}
						if calls > 1 || req.URL.String() != wantURL || req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Accept") != "application/json" || req.Header.Get(tc.header) != tc.prefix+tc.secret {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: tc.secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					wantCalls := 1
					if tc.id == "tradier-token" && (status == 401 || status == 403) {
						wantCalls = 2
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestTwentiethBatchTransportAndFallback(t *testing.T) {
	for _, tc := range batch20Contracts {
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
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret)
				if calls != 1 || r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
		})
	}
	for _, status := range []int{401, 403} {
		for _, cancelled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls > 2 {
					t.Fatal("too many probes")
				}
				code, body := status, `{"error":"denied"}`
				if calls == 2 {
					if req.URL.Host != "sandbox.tradier.com" {
						t.Fatal("wrong fallback host")
					}
					code, body = 200, `{"profile":{"id":"id-1","name":"name"}}`
				}
				if cancelled {
					cancel()
				}
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			r := verifyTradier(WithVerificationHTTPClient(ctx, client), "secret")
			cancel()
			if cancelled {
				if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			} else if calls != 2 || r.Status != VerificationVerified || r.Response != "" {
				t.Fatalf("calls=%d result=%+v", calls, r)
			}
		}
	}
}

func TestTwentiethBatchCredentialFamilies(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := map[string]string{"figma-pat": "", "clerk-secret-key": "CLERK_SECRET_KEY", "zeplin-token": "zeplin token", "adafruit-io-key": "adafruit io_key", "pipedream-api-key": "pipedream api_key", "line-messaging-token": "LINE_MESSAGING_TOKEN", "bannerbear-api-key": "bannerbear api_key", "elastic-email-api-key": "elastic_email api_key", "tradier-token": "tradier token", "triggerdev-api-key": ""}
	for _, tc := range batch20Contracts {
		input := contexts[tc.id] + ` = "` + tc.secret + `"`
		matches := registry[tc.id].Detect([]byte(input))
		if len(matches) != 1 || matches[0].Secret != tc.secret {
			t.Fatalf("%s failed whole credential capture: %+v", tc.id, matches)
		}
		input = contexts[tc.id] + ` = "` + tc.secret + strings.Repeat("Z", 300) + `"`
		if matches := registry[tc.id].Detect([]byte(input)); len(matches) != 0 {
			t.Fatalf("%s truncated oversized credential: %+v", tc.id, matches)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported family made a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, prefix := range []string{"figu_", "figo_", "figur_", "figuh_", "figor_", "figoh_"} {
		secret := prefix + strings.Repeat("A", 40)
		if matches := registry["figma-pat"].Detect([]byte(secret)); len(matches) != 1 || matches[0].Secret != secret {
			t.Fatalf("lost detection of %s", prefix)
		}
		if r := verifyFigma(ctx, secret); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("unexpected family result: %+v", r)
		}
	}
	if r := verifyTriggerDev(ctx, "tr_pat_"+strings.Repeat("A", 32)); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
		t.Fatalf("unexpected PAT result: %+v", r)
	}
	for _, prefix := range []string{"tr_dev_", "tr_prod_", "tr_stg_", "tr_preview_", "tr_dev_sk_", "tr_prod_sk_", "tr_stg_sk_", "tr_preview_sk_"} {
		secret := prefix + strings.Repeat("A", 32)
		if matches := registry["triggerdev-api-key"].Detect([]byte(secret)); len(matches) != 1 || matches[0].Secret != secret {
			t.Fatalf("lost detection of %s", prefix)
		}
	}
	for _, secret := range []string{strings.Repeat("a", 32), "aio_" + strings.Repeat("a", 32)} {
		if matches := registry["adafruit-io-key"].Detect([]byte(`adafruit io_key="` + secret + `"`)); len(matches) != 1 || matches[0].Secret != secret {
			t.Fatal("lost legacy or modern Adafruit credential")
		}
	}
	for _, secret := range []string{strings.Repeat("A", 172), "/" + strings.Repeat("A", 170) + "=", strings.Repeat("A", 171) + "/=="} {
		if matches := registry["line-messaging-token"].Detect([]byte(`LINE_MESSAGING_TOKEN="` + secret + `"`)); len(matches) != 1 || matches[0].Secret != secret {
			t.Fatalf("lost padded or slash-bearing LINE credential: %+v", matches)
		}
	}
}
