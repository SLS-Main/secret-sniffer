package detectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var batch27Contracts = []struct {
	id                              string
	verify                          Verifier
	secret, endpoint, header, value string
	valid, invalid                  []string
}{
	{"coinapi-key", verifyCoinAPI, "secret", "https://rest.coinapi.io/v1/exchanges/COINBASE", "X-CoinAPI-Key", "secret",
		[]string{`[]`, `[{"exchange_id":"COINBASE","name":"Coinbase","data_trade_end":null}]`},
		[]string{`{}`, `[{}]`, `[{"exchange_id":"OTHER","name":"Coinbase"}]`, `[{"exchange_id":"COINBASE","name":"Coinbase","error":"denied"}]`, `{"error":"Invalid API Key"}`}},
	{"etherscan-api-key", verifyEtherscan, "secret", "https://api.etherscan.io/v2/api?module=getapilimit&action=getapilimit&apikey=secret", "", "",
		[]string{`{"status":"1","message":"OK","result":{"creditsUsed":0,"creditsAvailable":0,"creditLimit":0,"limitInterval":"daily","intervalExpiryTimespan":"08:42:34"}}`},
		[]string{`{}`, `{"status":"1","message":"OK","result":"123"}`, `{"status":"0","message":"NOTOK","result":"Invalid API Key"}`, `{"status":"0","message":"NOTOK","result":"Max rate limit reached, please use API Key for higher rate limit"}`, `{"status":"1","message":"OK","result":{"creditsUsed":null,"creditsAvailable":0,"creditLimit":0,"limitInterval":"daily","intervalExpiryTimespan":"08:42:34"}}`, `{"status":"1","message":"OK","result":{"creditsUsed":"0","creditsAvailable":0,"creditLimit":0,"limitInterval":"daily","intervalExpiryTimespan":"08:42:34"}}`}},
	{"pagarme-live-key", verifyPagarMe, "ak_live_" + strings.Repeat("A", 30), "https://api.pagar.me/1/plans?count=1", "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("ak_live_"+strings.Repeat("A", 30)+":x")),
		[]string{`[]`, `[{"object":"plan","id":1,"name":"plan","amount":0,"days":0,"charges":null,"color":null}]`},
		[]string{`{}`, `{"data":[]}`, `[{"object":"order","id":1,"name":"plan","amount":0,"days":0}]`, `[{"object":"plan","id":"1","name":"plan","amount":0,"days":0}]`, `[{"object":"plan","id":1,"name":"plan","amount":0,"days":0,"errors":["denied"]}]`}},
	{"polygon-api-key", verifyPolygon, "secret", "https://api.massive.com/v1/marketstatus/now", "Authorization", "Bearer secret",
		[]string{`{"market":"closed","serverTime":"2026-09-27T00:00:00Z","earlyHours":false,"afterHours":false}`, `{"market":"extended-hours","serverTime":"2026-09-26T17:37:37-05:00","earlyHours":false,"afterHours":true,"exchanges":null}`},
		[]string{`{}`, `{"market":"closed","serverTime":"bad","earlyHours":false,"afterHours":false}`, `{"market":"closed","serverTime":"2026-09-27T00:00:00Z","earlyHours":false,"afterHours":null}`, `{"status":"ERROR","market":"closed","serverTime":"2026-09-27T00:00:00Z","earlyHours":false,"afterHours":false}`, `{"market":"closed","serverTime":"2026-09-27T00:00:00Z","earlyHours":"false","afterHours":false}`}},
	{"detectify-api-key", verifyDetectify, strings.Repeat("a", 32), "https://api.detectify.com/rest/v2/assets/?pageSize=1&include_subdomains=false", "X-Detectify-Key", strings.Repeat("a", 32),
		[]string{`{}`, `{"assets":[],"has_more":false}`, `{"assets":[{"token":"id","name":"example.com","status":"unverified","monitored":false}],"has_more":true,"next_marker":"ignored"}`},
		[]string{`{"assets":null,"has_more":false}`, `{"assets":[],"has_more":null}`, `{"assets":[{}],"has_more":false}`, `{"assets":[],"has_more":false,"code":401}`, `{"error":null}`, `{"assets":[{"token":"id","name":"example.com","status":"unverified","errors":["denied"]}],"has_more":false}`}},
	{"detectify-api-key", verifyDetectify, "01234567-89ab-cdef-0123-456789abcdef", "https://api.detectify.com/rest/v3/ips?limit=1", "Authorization", "01234567-89ab-cdef-0123-456789abcdef",
		[]string{`{"items":[]}`, `{"items":[{"id":"id","asset_id":"asset","team_id":"team","ip_address":"2001:db8::1","active":false,"enriched":false}],"pagination":{"next":"https://other.invalid"}}`},
		[]string{`{}`, `{"items":null}`, `{"items":[{}]}`, `{"items":[{"id":"id","asset_id":"asset","team_id":"team","ip_address":"not-an-IP"}]}`, `{"items":[],"type":"/invalid_request","status":400,"detail":"private-metadata"}`}},
	{"route4me-api-key", verifyRoute4Me, "secret", "https://api.route4me.com/api.v4/address_book.php?limit=1&offset=0&api_key=secret", "", "",
		[]string{`{"total":0,"results":[]}`, `{"total":1,"results":[{"address_id":1,"address_1":"private-metadata","first_name":null}]}`},
		[]string{`{}`, `{"total":null,"results":[]}`, `{"total":0,"results":null}`, `{"total":1,"results":[{"address_id":"1","address_1":"street"}]}`, `{"total":1,"results":[{"address_id":1}]}`}},
	{"smartlead-api-key", verifySmartlead, "secret", "https://server.smartlead.ai/api/v1/analytics/campaign/list?api_key=secret", "", "",
		[]string{`{"ok":true,"data":{"campaign_list":[]}}`, `{"ok":true,"data":{"campaign_list":[{"id":1,"name":"private-metadata"}]}}`},
		[]string{`{}`, `{"ok":false,"data":{"campaign_list":[]}}`, `{"ok":true,"data":{"campaign_list":null}}`, `{"ok":true,"data":{"campaign_list":[{"id":"1","name":"name"}]}}`, `{"ok":true,"data":{"campaign_list":[],"error":"denied"}}`}},
	{"ubidots-token", verifyUbidots, "secret", "https://industrial.api.ubidots.com/api/v2.0/devices/?page=1&page_size=1", "X-Auth-Token", "secret",
		[]string{`{"count":0,"results":[]}`, `{"count":1,"results":[{"id":"id","label":"label","isActive":false,"lastActivity":null}],"next":"https://other.invalid"}`},
		[]string{`{}`, `{"count":0,"results":null}`, `{"count":0,"results":[],"code":401001}`, `{"count":1,"results":[{"id":1,"label":"label"}]}`, `{"count":1,"results":[{"id":"id","label":"label","error":"denied"}]}`}},
	{"apimatic-api-key", verifyAPIMatic, "secret", "https://api.apimatic.io/account/profile", "Authorization", "X-Auth-Key secret",
		[]string{`{"Id":"id","Email":"mail","FullName":"","SecurityStamp":"private-metadata","ApiCopilotKeys":["private-metadata"]}`},
		[]string{`{}`, `{"Id":"id"}`, `{"Id":1,"Email":"mail"}`, `{"Id":"id","Email":"mail","error":"denied"}`, `<CodeGeneration>ok</CodeGeneration>`}},
	{"insightly-api-key", verifyInsightly, "secret", "https://api.na1.insightly.com/v3.1/Users/Me", "Authorization", "Basic c2VjcmV0Og==",
		[]string{`{"USER_ID":1,"EMAIL_ADDRESS":"mail","ACTIVE":false,"FIRST_NAME":null,"EMAIL_DROPBOX_IDENTIFIER":"private-metadata"}`},
		[]string{`{}`, `[]`, `{"USER_ID":"1","EMAIL_ADDRESS":"mail"}`, `{"USER_ID":null,"EMAIL_ADDRESS":"mail"}`, `{"USER_ID":1,"EMAIL_ADDRESS":"mail","error":"denied"}`, `{"Message":"Authorization has been denied for this request."}`}},
}

func checkBatch27Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch27Contracts[index]
	endpoint := tc.endpoint
	if tc.id == "insightly-api-key" && call < 3 {
		endpoint = "https://" + []string{"api.na1.insightly.com", "api.eu1.insightly.com", "api.au1.insightly.com"}[call] + "/v3.1/Users/Me"
	} else if call > 0 {
		t.Fatal("unexpected extra request")
	}
	if req.Method != http.MethodGet || req.URL.String() != endpoint || req.Header.Get("Accept") != "application/json" || (req.Body != nil && req.Body != http.NoBody) {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
	}
	if tc.header != "" && req.Header.Get(tc.header) != tc.value {
		t.Fatal("wrong authentication")
	}
	if tc.header != "Authorization" && req.Header.Get("Authorization") != "" {
		t.Fatal("unexpected authorization")
	}
	if tc.id == "detectify-api-key" && tc.header == "Authorization" && req.Header.Get("X-Detectify-Key") != "" {
		t.Fatal("mixed credential families")
	}
}

func TestTwentySeventhBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[d.Info().ID] = r
		}
	}
	seen := make(map[string]bool)
	for index, tc := range batch27Contracts {
		seen[tc.id] = true
		t.Run(tc.id+tc.secret, func(t *testing.T) {
			d := registry[tc.id]
			if d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `null`, `"ok"`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"errors":["private-metadata"]}`)
			for _, field := range []string{"error", "error_code", "errors"} {
				body := tc.valid[len(tc.valid)-1]
				var object identityPayload
				var array []identityPayload
				isArray := strings.HasPrefix(body, "[")
				if isArray {
					if err := json.Unmarshal([]byte(body), &array); err != nil || len(array) != 1 {
						t.Fatal("invalid fixture")
					}
					object = array[0]
				} else if err := json.Unmarshal([]byte(body), &object); err != nil {
					t.Fatal(err)
				}
				object[field] = json.RawMessage(`"private-metadata"`)
				var encoded []byte
				if isArray {
					encoded, _ = json.Marshal(array)
				} else {
					encoded, _ = json.Marshal(object)
				}
				bodies = append(bodies, string(encoded))
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch27Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: tc.secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want, wantCalls := VerificationUnknown, 1
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if tc.id == "insightly-api-key" && (status == 401 || status == 403) {
						wantCalls = 3
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
	if len(seen) != 10 {
		t.Fatal("expected ten verifiers")
	}
}

func TestTwentySeventhBatchFailures(t *testing.T) {
	for _, tc := range batch27Contracts {
		t.Run(tc.id+tc.secret, func(t *testing.T) {
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
}

func TestTwentySeventhBatchInsightlyFallback(t *testing.T) {
	index := len(batch27Contracts) - 1
	tc := batch27Contracts[index]
	for _, status := range []int{401, 403} {
		for _, cancelled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				checkBatch27Request(t, index, calls, req)
				calls++
				code, body := status, `{"Message":"Authorization has been denied"}`
				if calls == 3 {
					code, body = 200, tc.valid[0]
				}
				if cancelled {
					cancel()
				}
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			r := tc.verify(WithVerificationHTTPClient(ctx, client), tc.secret)
			cancel()
			if cancelled {
				if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			} else if calls != 3 || r.Status != VerificationVerified || r.Response != "" {
				t.Fatalf("calls=%d result=%+v", calls, r)
			}
		}
	}
}

func TestTwentySeventhBatchBoundariesAndFamilies(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	cases := []struct{ id, prefix, secret string }{
		{"coinapi-key", "coinapi ", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"},
		{"etherscan-api-key", "etherscan api_key", strings.Repeat("A", 34)},
		{"pagarme-live-key", "", "ak_live_" + strings.Repeat("A", 30)},
		{"polygon-api-key", "polygon.io token", strings.Repeat("A", 31) + "-"},
		{"detectify-api-key", "detectify api_key", strings.Repeat("a", 32)},
		{"detectify-api-key", "detectify api_key", "01234567-89ab-cdef-0123-456789abcdef"},
		{"detectify-api-key", "detectify api_key", strings.Repeat("Z", 64)},
		{"route4me-api-key", "route4me api_key", strings.Repeat("A", 32)},
		{"smartlead-api-key", "smartlead_api key", strings.Repeat("A", 31) + "-"},
		{"ubidots-token", "ubidots token", strings.Repeat("A", 31) + "-"},
		{"apimatic-api-key", "apimatic key", strings.Repeat("A", 63) + "-"},
		{"insightly-api-key", "insightly key", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
	}
	for _, tc := range cases {
		got := registry[tc.id].Detect([]byte(tc.prefix + `="` + tc.secret + `"`))
		if len(got) != 1 || got[0].Secret != tc.secret {
			t.Fatalf("%s lost credential: %+v", tc.id, got)
		}
		for _, suffix := range []string{"+suffix", "/suffix"} {
			if got := registry[tc.id].Detect([]byte(tc.prefix + `="` + tc.secret + suffix + `"`)); len(got) != 0 {
				t.Fatalf("%s truncated token", tc.id)
			}
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unsupported family sent"); return nil, nil })}
	for _, tc := range []struct {
		verify Verifier
		secret string
	}{{verifyPagarMe, "sk_" + strings.Repeat("A", 30)}, {verifyPagarMe, "ak_live_" + strings.Repeat("A", 31)}, {verifyDetectify, strings.Repeat("Z", 32)}, {verifyDetectify, strings.Repeat("a", 64)}} {
		if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("result=%+v", r)
		}
	}
}

func TestTwentySeventhBatchMetadataCap(t *testing.T) {
	for _, tc := range []struct {
		verify Verifier
		body   string
	}{{verifySmartlead, `{"ok":true,"data":{"campaign_list":[{"id":1,"name":"` + strings.Repeat("A", maxVerificationResponseBytes) + `"}]}}`}, {verifyAPIMatic, `{"Id":"id","Email":"mail","ApiCopilotKeys":["` + strings.Repeat("A", maxVerificationResponseBytes) + `"]}`}} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "secret"); calls != 1 || r.Status != VerificationUnknown || r.Response != "" {
			t.Fatalf("calls=%d result=%+v", calls, r)
		}
	}
}
