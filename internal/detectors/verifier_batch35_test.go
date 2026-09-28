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

var batch35Contracts = []struct {
	id, assignment, secret, fields, endpoint, header, prefix string
	valid, invalid                                           []string
}{
	{"salesblink-api-key", "SALESBLINK_API_KEY", "key-" + strings.Repeat("A", 64), "SALESBLINK_API_URL=https://run.salesblink.io/api/public/v1.0.0", "https://run.salesblink.io/api/public/v1.0.0/folders?limit=1&skip=0", "Authorization", "",
		[]string{`{"success":true,"data":[]}`, `{"success":true,"data":[{"id":"folder","name":"private-data"}]}`, `{"success":true,"data":[{"id":"folder","name":"folder","type":"email-sender"}]}`},
		[]string{`{"success":true}`, `{"success":false,"data":[]}`, `{"success":"true","data":[]}`, `{"success":true,"data":null}`, `{"success":true,"data":[{"id":1,"name":"folder"}]}`, `{"success":true,"data":[{"id":"folder","name":"folder","error":"denied"}]}`}},
	{"autoklose-api-key", "AUTOKLOSE_API_KEY", strings.Repeat("a", 32), "", "https://api.autoklose.com/api/me?api_token=" + strings.Repeat("a", 32), "", "",
		[]string{`{"id":241,"email":"private-data","role":"manager"}`, `{"id":241,"email":"email","role":"user","first_name":"","last_name":null,"team":""}`},
		[]string{`{"email":"email"}`, `{"id":"241","email":"email","role":"manager"}`, `{"id":241,"email":"email","role":null}`, `{"id":0,"email":"email","role":"manager"}`}},
	{"stormboard-api-key", "STORMBOARD_API_KEY", strings.Repeat("A", 40), "", "https://api.stormboard.com/users/test", "X-API-Key", "",
		[]string{`{"message":"Connected, w00t","status":200}`},
		[]string{`{"status":200}`, `{"message":"Connected, w00t","status":"200"}`, `{"message":"Connected, w00t","status":403}`, `{"message":"Not connected","status":200}`}},
	{"teletype-api-key", "TELETYPE_API_TOKEN", strings.Repeat("A", 64), "", "https://api.teletype.app/public/api/v1/project/details", "X-Auth-Token", "",
		[]string{`{"success":true,"data":{"id":"project","owner_id":"owner","name":"private-data","domain":"example","url":"https://other.invalid","createdAt":{"date":"date","timezone":"UTC"}},"errors":[],"errorsType":null}`},
		[]string{`{"success":true,"data":[]}`, `{"success":false,"data":null,"errors":[{"code":429}],"errorsType":"TooManyRequestsException"}`, `{"success":false,"data":null,"errors":[{"code":401}],"errorsType":"InvalidCredentialsException"}`, `{"success":true,"data":{"id":"project","name":"project"},"errors":[],"errorsType":null}`}},
	{"clustdoc-api-key", "CLUSTDOC_API_TOKEN", strings.Repeat("A", 40), "CLUSTDOC_API_URL=https://app.clustdoc.com/api/v2", "https://app.clustdoc.com/api/v2/tags?per_page=1&page=1", "Authorization", "Bearer ",
		[]string{`{"data":[],"meta":{"current_page":1,"per_page":1,"total":0}}`, `{"data":[{"id":1,"name":"private-data","color":null}],"meta":{"current_page":1,"per_page":1,"total":2},"links":{"next":"https://other.invalid"}}`},
		[]string{`{"data":[]}`, `{"data":null,"meta":{"current_page":1,"per_page":1,"total":0}}`, `{"data":[],"meta":{"current_page":"1","per_page":1,"total":0}}`, `{"data":[],"meta":{"current_page":1,"per_page":1,"total":0,"error":"denied"}}`, `{"data":[{"id":1,"name":"tag","error":"denied"}],"meta":{"current_page":1,"per_page":1,"total":1}}`, `{"data":[],"meta":{"current_page":1,"per_page":1,"total":0},"type":"unauthenticated"}`}},
	{"nozbeteams-api-token", "NOZBE_API_TOKEN", strings.Repeat("A", 16) + "_" + strings.Repeat("B", 64), "", "https://api4.nozbe.com/v1/api/teams?limit=1&offset=0&fields=id,name", "Authorization", "",
		[]string{`[]`, `[{"id":"ABCDEFGHIJKLMNOP","name":"private-data"}]`},
		[]string{`[{}]`, `[{"id":"short","name":"team"}]`, `[{"id":"ABCDEFGHIJKLMNOP","name":null}]`, `[{"id":"ABCDEFGHIJKLMNOP","name":"team","error":"denied"}]`}},
}

func TestThirtyFifthBatchContracts(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch35Contracts {
		t.Run(tc.id, func(t *testing.T) {
			c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
			safety := VerificationSafetyReadOnly
			if tc.id == "stormboard-api-key" {
				safety = VerificationSafetyAuthOnly
			}
			if c.Secret != tc.secret || c.VerificationSafety != safety {
				t.Fatalf("%+v", c)
			}
			bodies := append(append([]string{}, tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `"ok"`, `<html>Login</html>`, tc.valid[0]+" trailing")
			for _, field := range []string{"error", "errors", "error_code"} {
				var obj identityPayload
				if tc.id == "nozbeteams-api-token" {
					_ = json.Unmarshal([]byte(`{"id":"ABCDEFGHIJKLMNOP","name":"team"}`), &obj)
				} else {
					_ = json.Unmarshal([]byte(tc.valid[0]), &obj)
				}
				obj[field] = json.RawMessage(`"denied"`)
				raw, _ := json.Marshal(obj)
				body := string(raw)
				if tc.id == "nozbeteams-api-token" {
					body = "[" + body + "]"
				}
				bodies = append(bodies, body)
			}
			if tc.id == "teletype-api-key" {
				for _, replacement := range []struct{ old, new string }{
					{`"errors":[]`, `"errors":null`}, {`"errorsType":null`, `"errorsType":"TooManyRequestsException"`},
					{`"owner_id":"owner"`, `"owner_id":null`}, {`"timezone":"UTC"`, `"timezone":null`},
					{`"createdAt":{`, `"createdAt":{"error":"denied",`}, {`"data":{`, `"data":{"error":"denied",`},
				} {
					bodies = append(bodies, strings.Replace(tc.valid[0], replacement.old, replacement.new, 1))
				}
			}
			for _, status := range []int{200, 201, 204, 301, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.Method != http.MethodGet || req.URL.String() != tc.endpoint || req.Body != nil || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						if tc.header != "" && req.Header.Get(tc.header) != tc.prefix+tc.secret {
							t.Fatal("wrong authentication")
						}
						if tc.id == "autoklose-api-key" && (req.Header.Get("Authorization") != "" || req.URL.Query().Get("api_token") != tc.secret) {
							t.Fatal("wrong query authentication")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if calls != 1 || r.Status != want || r.Response != "" || strings.Contains(r.Message, "private-data") || strings.Contains(r.Message, tc.secret) {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestThirtyFifthBatchFailuresAndContext(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch35Contracts {
		c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
		for _, mode := range []string{"network", "read", "oversize", "cancel", "timeout"} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				switch mode {
				case "network":
					return nil, errors.New(tc.secret)
				case "read":
					return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
				case "cancel":
					return nil, context.Canceled
				case "timeout":
					return nil, context.DeadlineExceeded
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.valid[0] + strings.Repeat(" ", maxVerificationResponseBytes)))}, nil
			})}
			r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
			if calls != 1 || r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, tc.secret) {
				t.Fatalf("%s %s: %+v", tc.id, mode, r)
			}
		}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsupported context sent request")
			return nil, nil
		})}
		ctx := WithVerificationHTTPClient(context.Background(), client)
		for _, base := range []string{"", "https://other.invalid", "http://app.clustdoc.com/api/v2", "https://app.clustdoc.com:443/api/v2", "https://user@app.clustdoc.com/api/v2", "https://app.clustdoc.com/api/v2?token=secret", "https://app.clustdoc.com/api/v2#fragment", "https://app.clustdoc.com/api/v2.evil.invalid"} {
			altered := c
			altered.SecretParts = cloneStringMap(c.SecretParts)
			if altered.SecretParts == nil {
				altered.SecretParts = map[string]string{}
			}
			altered.SecretParts["endpoint"] = base
			if r := altered.Verify(ctx); r.Status != VerificationUnknown {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
		if len(registry[tc.id].Detect([]byte(tc.assignment+"="+tc.secret+"+suffix"))) != 0 {
			t.Fatalf("%s accepted truncated key", tc.id)
		}
		if tc.fields == "" {
			continue
		}
		key := tc.assignment + "=" + tc.secret
		field, value, _ := strings.Cut(tc.fields, "=")
		whole, _ := json.Marshal(map[string]string{tc.assignment: tc.secret, field: value})
		structured := batch30Candidate(t, registry[tc.id], string(whole))
		if c.VerificationCacheKey() != structured.VerificationCacheKey() {
			t.Fatalf("%s cache depends on serialization", tc.id)
		}
		primary, _ := json.Marshal(map[string]string{tc.assignment: tc.secret})
		other, _ := json.Marshal(map[string]string{field: value})
		for _, input := range []string{key, key + "\n\n" + tc.fields, key + "\n[other]\n" + tc.fields, key + "\n---\n" + tc.fields, key + "\n" + tc.fields + "\n" + field + "=conflict", `[` + string(primary) + `,` + string(other) + `]`, key + "\n" + strings.Repeat("# padding\n", 70) + tc.fields} {
			isolated := batch30Candidate(t, registry[tc.id], input)
			if isolated.VerificationCacheKey() == c.VerificationCacheKey() {
				t.Fatal("context crossed record boundary")
			}
			if r := isolated.Verify(ctx); r.Status != VerificationUnknown {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
	}
}

func TestThirtyFifthBatchBlockedNoNetwork(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("blocked verifier sent request"); return nil, nil })}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	blocked := []struct{ id, input, category string }{
		{"mailjetsms-api-token", "mailjetsms token=" + strings.Repeat("A", 32), "credential_type"},
		{"upwave-api-key", "upwave key=" + strings.Repeat("a", 32), "provider_contract"},
		{"cloudplan-api-key", "cloudplan key=" + strings.Repeat("A", 40), "provider_contract"},
		{"cloverly-api-key", "cloverly key=" + strings.Repeat("a", 28), "provider_contract"},
	}
	if len(batch35Contracts)+len(blocked) != 10 {
		t.Fatal("expected ten dispositions")
	}
	for _, tc := range blocked {
		c := batch30Candidate(t, registry[tc.id], tc.input)
		if registry[tc.id].Info().VerificationSafety != VerificationSafetyUnreviewed {
			t.Fatalf("%s incorrectly promoted", tc.id)
		}
		c.SecretParts = map[string]string{"endpoint": "https://other.invalid", "credential_type": "bearer", "secret": "untrusted-companion"}
		for _, policy := range []VerificationPolicy{{}, {AllowUnsafe: true}, {AllowUnreviewed: true}, {AllowUnreviewed: true, AllowUnsafe: true}} {
			r := c.VerifyWithPolicy(ctx, policy)
			want, category := VerificationNotAttempted, "unreviewed_verification_disabled"
			if policy.AllowUnreviewed {
				want, category = VerificationUnknown, tc.category
			}
			if r.Status != want || r.ErrorCategory != category || r.Response != "" || strings.Contains(r.Message, c.Secret) {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
		if r := registry[tc.id].(RegexDetector).Verifier(ctx, c.Secret); r.Status != VerificationUnknown || r.Response != "" {
			t.Fatalf("%s: %+v", tc.id, r)
		}
	}
}

func TestThirtyFifthBatchClustdocDeploymentIsolation(t *testing.T) {
	d := batch30Registry()["clustdoc-api-key"]
	key := "CLUSTDOC_API_TOKEN=" + strings.Repeat("A", 40)
	prod := batch30Candidate(t, d, key+"\nCLUSTDOC_API_URL=https://app.clustdoc.com/api/v2")
	sandbox := batch30Candidate(t, d, key+"\nCLUSTDOC_API_URL=https://sandbox.clustdoc.com/api/v2/")
	if prod.VerificationCacheKey() == sandbox.VerificationCacheKey() {
		t.Fatal("deployments share cache")
	}
	for _, status := range []int{200, 401, 403, 429, 503} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Host != "sandbox.clustdoc.com" {
				t.Fatal("sandbox key sent to another deployment")
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"data":[],"meta":{"current_page":1,"per_page":1,"total":0}}`))}, nil
		})}
		r := sandbox.Verify(WithVerificationHTTPClient(context.Background(), client))
		want := VerificationUnknown
		if status == 200 {
			want = VerificationVerified
		}
		if calls != 1 || r.Status != want {
			t.Fatalf("%+v calls=%d", r, calls)
		}
	}
}

func TestBlockedInventoryMakesNoRequestsEvenWithOptIn(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("blocked inventory contacted a provider")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	count := 0
	for _, detector := range DefaultRegistry() {
		if verificationAuditAssessments[detector.Info().ID].Status != VerificationAuditBlocked {
			continue
		}
		count++
		d := detector.(RegexDetector)
		if d.Info().VerificationSafety != VerificationSafetyUnreviewed || d.Verifier == nil {
			t.Fatalf("unexpected blocked disposition: %+v", d.Info())
		}
		c := Candidate{DetectorID: d.ID, Secret: "private-credential", Verifier: d.Verifier, CompositeVerifier: d.CompositeVerifier, VerificationSafety: d.VerificationSafety}
		r := c.VerifyWithPolicy(ctx, VerificationPolicy{AllowUnreviewed: true, AllowUnsafe: true})
		if r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, c.Secret) {
			t.Fatalf("%s: %+v", d.ID, r)
		}
	}
	if count != 16 {
		t.Fatalf("blocked inventory size=%d", count)
	}
}
