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

var batch23Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	auth, body     string
	valid, invalid []string
}{
	{"typeform-token", verifyTypeform, []string{"https://api.typeform.com/workspaces?page=1&page_size=1", "https://api.typeform.eu/workspaces?page=1&page_size=1"}, "Bearer secret", "",
		[]string{`{"total_items":0,"page_count":0,"items":[]}`, `{"total_items":1,"page_count":1,"items":[{"id":"id","name":"name","forms":null}]}`},
		[]string{`{"total_items":0,"page_count":0,"items":null}`, `{"total_items":0,"page_count":0,"items":[],"code":"AUTHENTICATION_FAILED"}`, `{"total_items":"0","page_count":0,"items":[]}`}},
	{"bitgo-access-token", verifyBitGo, []string{"https://app.bitgo.com/api/v2/user/me", "https://app.bitgo-test.com/api/v2/user/me"}, "Bearer secret", "",
		[]string{`{"user":{"id":"id","username":"user","isFrozen":true,"isActive":false}}`},
		[]string{`{"user":{"id":"id"}}`, `{"user":{"id":"id","username":null}}`, `{"user":{"id":"id","username":"user","error":"denied"}}`}},
	{"statuspage-api-key", verifyStatuspage, []string{"https://api.statuspage.io/v1/pages"}, "OAuth secret", "",
		[]string{`[]`, `[{"id":"id","name":"name","created_at":"date","domain":null}]`},
		[]string{`[{}]`, `[{"id":"id","name":"name","created_at":"date","error":"denied"}]`, `[{"id":"id","name":null,"created_at":"date"}]`}},
	{"sourcegraph-token", verifySourcegraphCloud, []string{"https://sourcegraph.com/.api/graphql"}, "token secret", `{"query":"query { currentUser { username } }"}`,
		[]string{`{"data":{"currentUser":{"username":"user"}}}`, `{"data":{"currentUser":{"username":"user"}},"errors":[]}`},
		[]string{`{"data":{"currentUser":null}}`, `{"data":{"currentUser":{"username":"user","error":"denied"}}}`, `{"data":{"currentUser":{"username":"user"}},"errors":[{"message":"denied"}]}`}},
	{"flutterwave-secret-key", verifyFlutterwave, []string{"https://api.flutterwave.com/v3/balances"}, "Bearer secret", "",
		[]string{`{"status":"success","data":[]}`, `{"status":"success","data":[{"currency":"USD","available_balance":-1.25,"ledger_balance":0}]}`},
		[]string{`{"status":"error","data":[]}`, `{"status":"success","data":[{"currency":"USD","available_balance":null,"ledger_balance":0}]}`, `{"status":"success","data":[{"currency":"USD","available_balance":"0","ledger_balance":0}]}`}},
	{"openweather-api-key", verifyOpenWeather, []string{"https://api.openweathermap.org/data/2.5/weather?lat=51.5074&lon=-0.1278&appid=secret"}, "", "",
		[]string{`{"cod":200,"dt":0,"coord":{"lat":51.5,"lon":-0.1},"main":{"temp":0},"weather":[{"id":800,"main":"Clear"}]}`},
		[]string{`{"weather":[],"main":{}}`, `{"cod":401,"dt":0,"coord":{"lat":0,"lon":0},"main":{"temp":0},"weather":[]}`, `{"cod":200,"dt":0,"coord":{"lat":0,"lon":0},"main":{"temp":null},"weather":[]}`}},
	{"tomorrowio-api-key", verifyTomorrowIO, []string{"https://api.tomorrow.io/v4/weather/realtime?location=0%2C0&apikey=secret"}, "", "",
		[]string{`{"data":{"time":"date","values":{"temperature":0,"cloudBase":null}},"location":{"lat":0,"lon":0}}`},
		[]string{`{"data":{},"location":{}}`, `{"data":{"time":"date","values":{"temperature":"0"}},"location":{"lat":0,"lon":0}}`, `{"data":{"time":"date","values":{"temperature":0}},"location":{"lat":0,"lon":0},"code":401}`}},
	{"here-api-key", verifyHERE, []string{"https://geocode.search.hereapi.com/v1/geocode?q=Berlin&limit=1&apiKey=secret"}, "", "",
		[]string{`{"items":[]}`, `{"items":[{"id":"here:id","title":"Berlin","resultType":"locality","position":{"lat":52.5,"lng":13.4}}]}`},
		[]string{`{"items":null}`, `{"items":[{}]}`, `{"items":[],"errorCode":"denied"}`, `{"items":[],"status":403}`}},
	{"worldweather-api-key", verifyWorldWeather, []string{"https://api.worldweatheronline.com/premium/v1/weather.ashx?q=London&num_of_days=0&format=json&key=secret"}, "", "",
		[]string{`{"data":{"request":[{"type":"City","query":"London"}],"current_condition":[{"observation_time":"12:00 PM","weatherCode":"113","temp_C":"-1"}]}}`},
		[]string{`{"data":{"request":[],"current_condition":[]}}`, `{"data":{"request":[],"current_condition":[{"observation_time":"time","weatherCode":"113","temp_C":"NaN"}]}}`, `{"data":{"error":[{"msg":"API key is invalid"}],"request":[],"current_condition":[{"observation_time":"time","weatherCode":"113","temp_C":"0"}]}}`}},
	{"infura-project-id", verifyInfura, []string{"https://mainnet.infura.io/v3/secret"}, "", `{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}`,
		[]string{`{"jsonrpc":"2.0","id":1,"result":"0x1"}`},
		[]string{`{"jsonrpc":"2.0","id":2,"result":"0x1"}`, `{"jsonrpc":"2.0","id":"1","result":"0x1"}`, `{"jsonrpc":"2.0","id":1,"result":"0x5"}`, `{"id":1,"result":"0x1"}`, `{"jsonrpc":"2.0","id":1,"result":"0x1","error":{"code":-32000}}`}},
}

func checkBatch23Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch23Contracts[index]
	method, body := http.MethodGet, ""
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		body = string(b)
	}
	if tc.body != "" {
		method = http.MethodPost
		if req.Header.Get("Content-Type") != "application/json" {
			t.Fatal("missing JSON media type")
		}
	}
	if call >= len(tc.urls) || req.URL.String() != tc.urls[call] || req.Method != method || body != tc.body || req.Header.Get("Authorization") != tc.auth || req.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected %s %s body=%s", req.Method, req.URL, body)
	}
}

func TestTwentyThirdBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	if len(batch23Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	for index, tc := range batch23Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			if d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing")
			if tc.id != "statuspage-api-key" {
				for _, field := range []string{"error", "errors", "error_code"} {
					var p map[string]json.RawMessage
					if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
						t.Fatal(err)
					}
					p[field] = json.RawMessage(`"private-metadata"`)
					b, _ := json.Marshal(p)
					bodies = append(bodies, string(b))
				}
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch23Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: "secret", Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					wantCalls := 1
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

func TestTwentyThirdBatchTransportAndFallback(t *testing.T) {
	for index, tc := range batch23Contracts {
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
						checkBatch23Request(t, index, calls, req)
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

func TestTwentyThirdBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := []string{"", "app.bitgo-test.com token", "statuspage key", "", "", "openweather key", "tomorrowio key", "hereapi key", "world_weather key", "infura api_key"}
	secrets := []string{"tfp_" + strings.Repeat("A", 40), strings.Repeat("A", 31) + "-", strings.Repeat("a", 36), "sgp_" + strings.Repeat("a", 40), "FLWSECK_TEST-" + strings.Repeat("a", 32) + "-X", strings.Repeat("a", 32), strings.Repeat("A", 32), strings.Repeat("A", 42) + "-", strings.Repeat("A", 32), strings.Repeat("a", 32)}
	for i, tc := range batch23Contracts {
		got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `"`))
		if len(got) != 1 || got[0].Secret != secrets[i] {
			t.Fatalf("%s lost whole token: %+v", tc.id, got)
		}
		if got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `+suffix"`)); len(got) != 0 {
			t.Fatalf("%s truncated token", tc.id)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("local Sourcegraph token submitted")
		return nil, nil
	})}
	secret := "sgp_local_" + strings.Repeat("a", 40)
	if got := registry["sourcegraph-token"].Detect([]byte(secret)); len(got) != 1 {
		t.Fatal("local token no longer detected")
	}
	if r := verifySourcegraphCloud(WithVerificationHTTPClient(context.Background(), client), secret); r.Status != VerificationUnsupported {
		t.Fatalf("result=%+v", r)
	}
}

func TestTwentyThirdBatchStatuspageResponseCap(t *testing.T) {
	body := `[{"id":"id","name":"` + strings.Repeat("A", maxVerificationResponseBytes) + `","created_at":"date"}]`
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	if r := verifyStatuspage(WithVerificationHTTPClient(context.Background(), client), "secret"); r.Status != VerificationUnknown || r.Response != "" {
		t.Fatalf("result=%+v", r)
	}
}
