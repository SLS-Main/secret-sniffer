package detectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerificationStatusesAndFiltering(t *testing.T) {
	candidate := Candidate{DetectorID: "test", Name: "Test", Secret: "secret-value"}
	if got := ToFindingAt(candidate, "file", "", 1, 1, false).Verification.Status; got != VerificationNotAttempted {
		t.Fatalf("disabled verification status=%q", got)
	}
	if got := ToFindingAt(candidate, "file", "", 1, 1, true).Verification.Status; got != VerificationUnsupported {
		t.Fatalf("unsupported verification status=%q", got)
	}
	statuses := []VerificationStatus{VerificationVerified, VerificationUnverified, VerificationUnknown, VerificationNotAttempted, VerificationUnsupported}
	findings := make([]Finding, 0, len(statuses))
	for _, status := range statuses {
		findings = append(findings, Finding{DetectorID: string(status), Verification: VerificationResult{Status: status}})
	}
	allowed, err := ParseVerificationStatuses("verified,unknown")
	if err != nil {
		t.Fatal(err)
	}
	filtered := FilterVerification(findings, allowed)
	if len(filtered) != 2 || filtered[0].Verification.Status != VerificationVerified || filtered[1].Verification.Status != VerificationUnknown {
		t.Fatalf("unexpected filtered findings: %#v", filtered)
	}
	for _, status := range statuses {
		allowed, err := ParseVerificationStatuses(string(status))
		if err != nil {
			t.Fatal(err)
		}
		if got := FilterVerification(findings, allowed); len(got) != 1 || got[0].Verification.Status != status {
			t.Fatalf("filter %q returned %#v", status, got)
		}
	}
	if _, err := ParseVerificationStatuses("invalid"); err == nil {
		t.Fatal("expected invalid verification status error")
	}
}

func TestVerifyHTTPRequestCapturesBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("response ", 30)))
	}))
	defer server.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := verifyHTTPRequest(context.Background(), req)
	if result.Status != VerificationVerified {
		t.Fatalf("status=%q", result.Status)
	}
	if len([]rune(result.Response)) != 100 {
		t.Fatalf("response length=%d, response=%q", len([]rune(result.Response)), result.Response)
	}
}

func TestVerifyHTTPRequestClassifierPreservesAmbiguousAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"token_unauthorized"}`))
	}))
	defer server.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := verifyHTTPRequestWithClassifier(context.Background(), req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && strings.Contains(string(body), "token_unauthorized") {
			return unknownVerificationResult("authorization", "ambiguous authorization"), true
		}
		return VerificationResult{}, false
	})
	if result.Status != VerificationUnknown || result.ErrorCategory != "authorization" || result.Response != `{"code":"token_unauthorized"}` {
		t.Fatalf("unexpected classified result: %#v", result)
	}
}

func TestGraphQLIdentityClassifierRequiresAuthenticatedData(t *testing.T) {
	classifier := classifyGraphQLIdentity("id")
	result, handled := classifier(http.StatusOK, []byte(`{"data":{"me":{"id":"user-1"}}}`))
	if !handled || result.Status != VerificationVerified {
		t.Fatalf("expected verified identity: handled=%v result=%#v", handled, result)
	}
	result, handled = classifier(http.StatusOK, []byte(`{"data":{"me":null},"errors":[{"message":"Not Authenticated"}]}`))
	if !handled || result.Status != VerificationUnknown || result.ErrorCategory != "authorization" {
		t.Fatalf("expected unknown GraphQL auth result: handled=%v result=%#v", handled, result)
	}
	if _, handled = classifier(http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`)); handled {
		t.Fatal("non-success status should use the shared HTTP classifier")
	}
}

func TestContextDependentCredentialVariantsRemainUnsupported(t *testing.T) {
	if result := verifyNewRelic(context.Background(), "NRII-example"); result.Status != VerificationUnsupported {
		t.Fatalf("New Relic ingest result=%#v", result)
	}
	if result := verifyLaunchDarkly(context.Background(), "sdk-example"); result.Status != VerificationUnsupported {
		t.Fatalf("LaunchDarkly SDK result=%#v", result)
	}
}

func TestDropboxVerifierUsesReadOnlyRPCAndRecognizesMissingScope(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.String() != "https://api.dropboxapi.com/2/users/get_current_account" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", req.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(`{"error_summary":"missing_scope"}`)), Header: make(http.Header)}, nil
	})}
	result := verifyDropbox(WithVerificationHTTPClient(context.Background(), client), "token")
	if result.Status != VerificationVerified || result.Response == "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestGoCardlessVerifierSelectsSandboxEndpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api-sandbox.gocardless.com" || req.Header.Get("GoCardless-Version") != "2015-07-06" {
			t.Fatalf("unexpected request: %s headers=%v", req.URL, req.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"creditors":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyGoCardless(WithVerificationHTTPClient(context.Background(), client), "sandbox_token")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDeepgramVerifierDistinguishesScopeFromInvalidAuth(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "scope", body: `{"err_code":"INSUFFICIENT_PERMISSIONS"}`, status: VerificationVerified},
		{name: "invalid", body: `{"err_code":"INVALID_AUTH","err_msg":"Invalid credentials."}`, status: VerificationUnverified},
		{name: "ambiguous", body: `{"error":"forbidden"}`, status: VerificationUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "Token secret" {
					t.Fatalf("authorization=%q", req.Header.Get("Authorization"))
				}
				return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}
			result := verifyDeepgram(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != test.status {
				t.Fatalf("status=%q result=%#v", result.Status, result)
			}
		})
	}
}

func TestDynalistVerifierUsesProviderResultCode(t *testing.T) {
	tests := []struct {
		code   string
		status VerificationStatus
	}{
		{code: "OK", status: VerificationVerified},
		{code: "InvalidToken", status: VerificationUnverified},
		{code: "TooManyRequests", status: VerificationUnknown},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil || !strings.Contains(string(body), `"token":"secret"`) {
					t.Fatalf("request body=%q err=%v", string(body), err)
				}
				response := `{"_code":"` + test.code + `"}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
			})}
			result := verifyDynalist(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != test.status {
				t.Fatalf("status=%q result=%#v", result.Status, result)
			}
		})
	}
}

func TestGrafanaVerifierRecognizesAuthenticatedScopeFailure(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(`{"message":"required scope accesspolicies:read"}`)), Header: make(http.Header)}, nil
	})}
	result := verifyGrafanaCloud(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestApolloVerifierUsesLoginStateInsideSuccessResponse(t *testing.T) {
	for _, test := range []struct {
		body   string
		status VerificationStatus
	}{
		{body: `{"healthy":true,"is_logged_in":true}`, status: VerificationVerified},
		{body: `{"healthy":true,"is_logged_in":false}`, status: VerificationUnverified},
		{body: `{"healthy":false,"is_logged_in":false}`, status: VerificationUnknown},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
		})}
		result := verifyApollo(WithVerificationHTTPClient(context.Background(), client), "secret")
		if result.Status != test.status {
			t.Fatalf("body=%s status=%q result=%#v", test.body, result.Status, result)
		}
	}
}

func TestUptimeRobotVerifierUsesApplicationStatus(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil || !strings.Contains(string(body), "api_key=secret") {
			t.Fatalf("request body=%q err=%v", string(body), err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"stat":"fail","error":{"parameter_name":"api_key","message":"invalid api key"}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyUptimeRobot(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestProtocolsIOVerifierRequiresAuthenticatedUser(t *testing.T) {
	for _, test := range []struct {
		body   string
		status VerificationStatus
	}{
		{body: `{"status_code":0,"user":{"id":1}}`, status: VerificationVerified},
		{body: `{"status_code":0}`, status: VerificationUnknown},
		{body: `{"status_code":1218}`, status: VerificationUnverified},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
		})}
		result := verifyProtocolsIO(WithVerificationHTTPClient(context.Background(), client), "secret")
		if result.Status != test.status {
			t.Fatalf("body=%s status=%q result=%#v", test.body, result.Status, result)
		}
	}
}

func TestMailsacVerifierRejectsNullSuccessBody(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("null")), Header: make(http.Header)}, nil
	})}
	result := verifyMailsac(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestVirusTotalVerifierAcceptsAuthenticatedSentinelMiss(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("x-apikey") != "secret" || !strings.HasSuffix(req.URL.Path, strings.Repeat("0", 64)) {
			t.Fatalf("unexpected request: %s headers=%v", req.URL, req.Header)
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"NotFoundError"}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyVirusTotal(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestWeightsAndBiasesVerifierRejectsNullViewer(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "api" || password != "secret" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":null}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyWeightsAndBiases(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSquareApplicationSecretDoesNotMakeNetworkRequest(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("Square application secret should not make a bearer request")
		return nil, nil
	})}
	result := verifySquare(WithVerificationHTTPClient(context.Background(), client), "sq0csp-secret")
	if result.Status != VerificationUnsupported {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestCoinlayerVerifierRecognizesQuotaAsAuthenticated(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("access_key") != "secret" {
			t.Fatalf("access key query=%q", req.URL.RawQuery)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":false,"error":{"code":104}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyCoinlayer(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestMapboxVerifierUsesProviderTokenStatus(t *testing.T) {
	for _, test := range []struct {
		code   string
		status VerificationStatus
	}{
		{code: "TokenValid", status: VerificationVerified},
		{code: "TokenRevoked", status: VerificationUnverified},
		{code: "ScopeRequired", status: VerificationUnknown},
	} {
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Query().Get("access_token") != "secret" {
				t.Fatalf("access token query=%q", req.URL.RawQuery)
			}
			body := `{"code":"` + test.code + `"}`
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		result := verifyMapbox(WithVerificationHTTPClient(context.Background(), client), "secret")
		if result.Status != test.status {
			t.Fatalf("code=%s status=%q result=%#v", test.code, result.Status, result)
		}
	}
}

func TestStoryblokAccessVerifierUsesTokenQuery(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("token") != "secret" || req.URL.Path != "/v2/cdn/spaces/me" {
			t.Fatalf("unexpected request: %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"space":{"id":1,"name":"test","version":1}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyStoryblokAccess(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestZillizVerifierUsesApplicationCode(t *testing.T) {
	for _, test := range []struct {
		body   string
		status VerificationStatus
	}{
		{body: `{"code":0,"data":[]}`, status: VerificationVerified},
		{body: `{"code":80001}`, status: VerificationUnverified},
		{body: `not-json`, status: VerificationUnknown},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
		})}
		result := verifyZilliz(WithVerificationHTTPClient(context.Background(), client), "secret")
		if result.Status != test.status {
			t.Fatalf("body=%s status=%q result=%#v", test.body, result.Status, result)
		}
	}
}

func TestFlickrVerifierRejectsInvalidKeyCode(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("method") != "flickr.test.echo" || req.URL.Query().Get("api_key") != "secret" {
			t.Fatalf("unexpected query: %q", req.URL.RawQuery)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"stat":"fail","code":100}`)), Header: make(http.Header)}, nil
	})}
	result := verifyFlickr(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestOnfidoVerifierDerivesCanadianEndpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.ca.onfido.com" || req.Header.Get("Authorization") != "Token token=api_live_ca.secret" {
			t.Fatalf("unexpected request: %s headers=%v", req.URL, req.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"applicants":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyOnfido(WithVerificationHTTPClient(context.Background(), client), "api_live_ca.secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestNylasRejectionRemainsUnknownForBroadCredentialDetector(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)), Header: make(http.Header)}, nil
	})}
	result := verifyNylas(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnknown || result.ErrorCategory != "credential_type" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBraintreeVerifierSelectsEnvironmentAndGraphQLAuthError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "payments.sandbox.braintree-api.com" || req.Header.Get("Braintree-Version") != "2019-01-01" {
			t.Fatalf("unexpected request: %s headers=%v", req.URL, req.Header)
		}
		body := `{"errors":[{"extensions":{"errorClass":"AUTHENTICATION"}}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyBraintree(WithVerificationHTTPClient(context.Background(), client), "access_token$sandbox$merchant$secret")
	if result.Status != VerificationUnverified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTwelveDataVerifierRequiresQuotaFields(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	result := verifyTwelveData(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnknown {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSingleStoreRejectsUnknownCredentialSubtypeWithoutNetwork(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported SingleStore credential should not make a request")
		return nil, nil
	})}
	result := verifySingleStore(WithVerificationHTTPClient(context.Background(), client), "not-a-management-key")
	if result.Status != VerificationUnsupported {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestAshbyVerifierDoesNotTrustFalseSuccessFlag(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, _, ok := req.BasicAuth()
		if !ok || username != "secret" {
			t.Fatalf("unexpected basic auth: username=%q ok=%v", username, ok)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":false}`)), Header: make(http.Header)}, nil
	})}
	result := verifyAshby(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnknown {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestCloudinaryVerifierUsesSelfContainedCredentials(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "123456789012345" || password != "abcdefghijklmnopqrstuvwxyz1" || req.URL.Path != "/v1_1/cloud/config" {
			t.Fatalf("unexpected request: %s username=%q password=%q ok=%v", req.URL, username, password, ok)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"cloud_name":"cloud"}`)), Header: make(http.Header)}, nil
	})}
	result := verifyCloudinary(WithVerificationHTTPClient(context.Background(), client), "cloudinary://123456789012345:abcdefghijklmnopqrstuvwxyz1@cloud")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSourcegraphLocalTokenDoesNotUseCloudEndpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("local Sourcegraph token should not make a cloud request")
		return nil, nil
	})}
	result := verifySourcegraphCloud(WithVerificationHTTPClient(context.Background(), client), "sgp_local_secret")
	if result.Status != VerificationUnsupported {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestGrowthBookClientKeyDoesNotUseSecretAPI(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("GrowthBook client key should not make a secret API request")
		return nil, nil
	})}
	result := verifyGrowthBook(WithVerificationHTTPClient(context.Background(), client), "sdk-client-key")
	if result.Status != VerificationUnsupported {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestConfigCatVerifierPreservesEmbeddedPathSegments(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/configuration-files/part-one/part-two/config_v6.json" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"f":{}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyConfigCat(WithVerificationHTTPClient(context.Background(), client), "part-one/part-two")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestIBMCloudVerifierSuppressesMintedAccessToken(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "bx" || password != "bx" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		body := `{"access_token":"new-sensitive-token","token_type":"Bearer","expires_in":3600}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyIBMCloud(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEtherscanVerifierUsesApplicationStatus(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("apikey") != "secret" {
			t.Fatalf("api key query=%q", req.URL.RawQuery)
		}
		body := `{"status":"0","message":"NOTOK","result":"Invalid API Key"}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyEtherscan(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestReadOnlyAPIClassifier(t *testing.T) {
	classifier := classifyReadOnlyAPI([]string{"data", "location"}, "invalid api key")
	tests := []struct {
		name       string
		statusCode int
		body       string
		status     VerificationStatus
		handled    bool
	}{
		{name: "valid", statusCode: http.StatusOK, body: `{"data":{"time":"now"},"location":{"lat":0}}`, status: VerificationVerified, handled: true},
		{name: "invalid in successful response", statusCode: http.StatusOK, body: `{"error":"Invalid API key"}`, status: VerificationUnverified, handled: true},
		{name: "quota", statusCode: http.StatusOK, body: `{"error":"quota exhausted"}`, status: VerificationUnknown, handled: true},
		{name: "malformed", statusCode: http.StatusOK, body: `{`, status: VerificationUnknown, handled: true},
		{name: "rate limited", statusCode: http.StatusTooManyRequests, body: `{}`, handled: false},
		{name: "server error", statusCode: http.StatusBadGateway, body: `{}`, handled: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, handled := classifier(tt.statusCode, []byte(tt.body))
			if handled != tt.handled || result.Status != tt.status {
				t.Fatalf("result=%#v handled=%v", result, handled)
			}
		})
	}
}

func TestVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"abuseipdb-api-key": false, "accuweather-api-key": false, "currencylayer-api-key": false,
		"exchangeratesapi-api-key": false, "financialmodelingprep-api-key": false, "finnhub-api-key": false,
		"fixerio-api-key": false, "geocodio-api-key": false, "here-api-key": false,
		"ipgeolocation-api-key": false, "ipstack-api-key": false, "mapquest-api-key": false,
		"marketstack-api-key": false, "openweather-api-key": false, "polygon-api-key": false,
		"positionstack-api-key": false, "tomorrowio-api-key": false, "tradier-token": false,
		"weatherstack-api-key": false, "worldweather-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestAbuseIPDBVerifierUsesKeyHeader(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Key") != "secret" || req.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected headers: %#v", req.Header)
		}
		body := `{"data":{"ipAddress":"192.0.2.1","abuseConfidenceScore":0}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyAbuseIPDB(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestNextVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"aviationstack-api-key": false, "calendarific-api-key": false, "commodities-api-key": false,
		"countrylayer-api-key": false, "currencyfreaks-api-key": false, "currencyscoop-api-key": false,
		"ethplorer-api-key": false, "fastforex-api-key": false, "geoapify-api-key": false,
		"graphhopper-api-key": false, "ipqualityscore-api-key": false, "kickbox-api-key": false,
		"numverify-api-key": false, "openuv-api-key": false, "pandascore-api-key": false,
		"vatlayer-api-key": false, "veriphone-api-key": false, "vpnapi-key": false,
		"walkscore-api-key": false, "weatherbit-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestIPQualityScoreVerifierClassifiesApplicationStatus(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "valid", body: `{"success":true,"message":"Success.","fraud_score":0}`, status: VerificationVerified},
		{name: "invalid", body: `{"success":false,"message":"Invalid or unauthorized key. Please check the API key and try again."}`, status: VerificationUnverified},
		{name: "no credits", body: `{"success":false,"message":"You have insufficient credits to make this query."}`, status: VerificationVerified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.EscapedPath() != "/api/json/ip/secret/8.8.8.8" {
					t.Fatalf("path=%q", req.URL.EscapedPath())
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyIPQualityScore(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestWalkScoreVerifierClassifiesProviderStatus(t *testing.T) {
	tests := []struct {
		status int
		want   VerificationStatus
	}{
		{status: 1, want: VerificationVerified},
		{status: 2, want: VerificationVerified},
		{status: 40, want: VerificationUnverified},
		{status: 41, want: VerificationVerified},
		{status: 42, want: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.status), func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				body := fmt.Sprintf(`{"status":%d}`, tt.status)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			result := verifyWalkScore(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.want {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestOpenUVVerifierUsesAccessTokenHeader(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("x-access-token") != "secret" {
			t.Fatalf("x-access-token=%q", req.Header.Get("x-access-token"))
		}
		body := `{"result":{"uv":0,"uv_time":"now"}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyOpenUV(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestThirdVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"abstract-api-key": false, "apilayer-key": false, "browshot-api-key": false,
		"buttercms-api-token": false, "datagov-api-key": false, "diffbot-api-token": false,
		"infura-project-id": false, "ipapi-api-key": false, "languagelayer-api-key": false,
		"mailmodo-api-key": false, "moralis-api-key": false, "pixabay-api-key": false,
		"rawg-api-key": false, "restpack-screenshot-api-key": false, "route4me-api-key": false,
		"salesblink-api-key": false, "spoonacular-api-key": false, "tomtom-api-key": false,
		"unsplash-access-key": false, "visualcrossing-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestInfuraVerifierRequiresJSONRPCResult(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status VerificationStatus
	}{
		{name: "valid", code: http.StatusOK, body: `{"jsonrpc":"2.0","id":1,"result":"0x1234"}`, status: VerificationVerified},
		{name: "invalid", code: http.StatusUnauthorized, body: `invalid project id`, status: VerificationUnverified},
		{name: "missing result", code: http.StatusOK, body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost || req.URL.EscapedPath() != "/v3/secret" || req.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("unexpected request: %s %s %#v", req.Method, req.URL.EscapedPath(), req.Header)
				}
				return &http.Response{StatusCode: tt.code, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyInfura(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestTomTomVerifierRequiresPNG(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status VerificationStatus
	}{
		{name: "valid", code: http.StatusOK, body: "\x89PNG\r\n\x1a\ncontent", status: VerificationVerified},
		{name: "invalid", code: http.StatusUnauthorized, body: `{"detailedError":{"message":"You are missing valid authentication credentials"}}`, status: VerificationUnverified},
		{name: "unexpected success", code: http.StatusOK, body: `not an image`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tt.code, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyTomTom(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestDiffbotVerifierSuppressesAccountResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("token") != "secret" {
			t.Fatalf("token query=%q", req.URL.Query().Get("token"))
		}
		body := `{"token":"secret","status":"active","plan":"paid","planCredits":100,"email":"private@example.com"}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyDiffbot(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRestpackScreenshotVerifierPreservesSubscriptionAmbiguity(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Access-Token") != "secret" {
			t.Fatalf("X-Access-Token=%q", req.Header.Get("X-Access-Token"))
		}
		body := `{"error":"The access token is invalid or you are not subscribed to any plan.","extensions":{"code":"InvalidAccessToken","status":403}}`
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyRestpackScreenshot(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnknown || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestFourthVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"alchemy-api-key": false, "canny-api-key": false, "codequiry-api-key": false,
		"detectlanguage-api-key": false, "dyspatch-api-key": false, "geckoboard-api-key": false,
		"ip2location-api-key": false, "ipinfodb-api-key": false, "klipfolio-api-key": false,
		"linkpreview-api-key": false, "moosend-api-key": false, "proxycrawl-api-token": false,
		"scraperapi-key": false, "scrapestack-api-key": false, "serpstack-api-key": false,
		"signupgenius-api-key": false, "twitter-bearer-token": false, "userstack-api-key": false,
		"whoxy-api-key": false, "yelp-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestAlchemyVerifierUsesReadOnlyJSONRPC(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.EscapedPath() != "/v2/secret" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.EscapedPath())
		}
		body, err := io.ReadAll(req.Body)
		if err != nil || !strings.Contains(string(body), `"method":"eth_blockNumber"`) {
			t.Fatalf("body=%q err=%v", body, err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":"0x1234"}`)), Header: make(http.Header)}, nil
	})}
	result := verifyAlchemy(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestIPInfoDBVerifierUsesApplicationStatus(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "valid", body: `{"statusCode":"OK","ipAddress":"8.8.8.8","countryCode":"US"}`, status: VerificationVerified},
		{name: "invalid", body: `{"statusCode":"ERROR","message":"Invalid API key.","ipAddress":"8.8.8.8"}`, status: VerificationUnverified},
		{name: "ambiguous", body: `{"statusCode":"ERROR","message":"Quota exceeded"}`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyIPInfoDB(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestFetchedExampleVerifierRequiresSentinelContent(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status VerificationStatus
	}{
		{name: "valid", code: http.StatusOK, body: `<html><title>Example Domain</title></html>`, status: VerificationVerified},
		{name: "invalid", code: http.StatusUnauthorized, body: `Unauthorized request, please make sure your API key is valid.`, status: VerificationUnverified},
		{name: "unexpected success", code: http.StatusOK, body: `<html>proxy error</html>`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tt.code, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyScraperAPI(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestCannyVerifierSuppressesPrivateBoardResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil || !strings.Contains(string(body), `"apiKey":"secret"`) {
			t.Fatalf("body=%q err=%v", body, err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"boards":[{"name":"private"}]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyCanny(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestFifthVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"airvisual-api-key": false, "ambee-api-key": false, "beamer-api-key": false,
		"craftmypdf-api-key": false, "currentsapi-api-key": false, "flightapi-key": false,
		"glassnode-api-key": false, "holidayapi-key": false, "mockaroo-api-key": false,
		"newscatcher-api-key": false, "peopledatalabs-api-key": false, "shotstack-api-key": false,
		"simfin-api-key": false, "sportsmonk-api-token": false, "stockdata-api-key": false,
		"stormglass-api-key": false, "travelpayouts-api-key": false, "uclassify-api-key": false,
		"upcdatabase-api-key": false, "worldcoinindex-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestPeopleDataLabsVerifierUsesAuthFirstValidation(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status VerificationStatus
	}{
		{name: "authenticated validation error", code: http.StatusBadRequest, body: `{"status":400,"error":{"type":["invalid_request_error"],"message":"Missing required input"}}`, status: VerificationVerified},
		{name: "invalid", code: http.StatusUnauthorized, body: `{"status":401,"error":{"type":["authentication_error"],"message":"Your request contained an invalid api key"}}`, status: VerificationUnverified},
		{name: "exhausted", code: http.StatusPaymentRequired, body: `{"status":402}`, status: VerificationVerified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("X-Api-Key") != "secret" {
					t.Fatalf("X-Api-Key=%q", req.Header.Get("X-Api-Key"))
				}
				return &http.Response{StatusCode: tt.code, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyPeopleDataLabs(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestUPCDatabaseVerifierRejectsHTTP200Error(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("Authorization=%q", req.Header.Get("Authorization"))
		}
		body := `{"success":false,"error":{"message":"Your API Key is invalid. Please check the format."}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyUPCDatabase(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBeamerVerifierValidatesURLAndSuppressesResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Beamer-Api-Key") != "secret" {
			t.Fatalf("Beamer-Api-Key=%q", req.Header.Get("Beamer-Api-Key"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`"https://example.getbeamer.com"`)), Header: make(http.Header)}, nil
	})}
	result := verifyBeamer(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestShotstackVerifierTriesBothEnvironments(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("x-api-key") != "secret" {
			t.Fatalf("x-api-key=%q", req.Header.Get("x-api-key"))
		}
		if strings.Contains(req.URL.Path, "/stage/") {
			body := `{"detail":"Invalid or disabled API key for the Sandbox API"}`
			return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		body := `{"success":true,"response":{"templates":[]}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyShotstack(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" || requests != 2 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestSixthVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"apitemplate-api-key": false, "autoklose-api-key": false, "besttime-api-key": false,
		"convertapi-secret": false, "happyscribe-api-key": false, "iconfinder-api-key": false,
		"nightfall-api-key": false, "nimble-api-key": false, "partnerstack-api-key": false,
		"pepipost-api-key": false, "replyio-api-key": false, "sendbird-organization-api-token": false,
		"shipday-api-key": false, "signable-api-key": false, "signaturit-api-key": false,
		"simplesat-api-key": false, "snipcart-api-key": false, "ticket-tailor-api-key": false,
		"uplead-api-key": false, "zenkit-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestBestTimeVerifierRejectsHTTP200InvalidKey(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.EscapedPath() != "/api/v1/keys/pri_secret" {
			t.Fatalf("path=%q", req.URL.EscapedPath())
		}
		body := `{"api_key_private":"masked","status":"Error","valid":false,"message":"Invalid api_key_private"}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyBestTime(WithVerificationHTTPClient(context.Background(), client), "pri_secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestReplyIOVerifierRejectsEmpty401(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Api-Key") != "secret" {
			t.Fatalf("X-Api-Key=%q", req.Header.Get("X-Api-Key"))
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	result := verifyReplyIO(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTicketTailorVerifierPreserves403Ambiguity(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "secret" || password != "" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		body := `{"error_code":"FORBIDDEN","message":"Key lacks permission"}`
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyTicketTailor(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnknown || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSignaturitVerifierTriesSandbox(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("Authorization=%q", req.Header.Get("Authorization"))
		}
		if req.URL.Host == "api.signaturit.com" {
			body := `{"error":"invalid_grant","error_message":"The access token provided is invalid."}`
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"signatures":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifySignaturit(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" || requests != 2 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestSeventhVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"carboninterface-api-key": false, "clearbit-api-key": false, "debounce-api-key": false,
		"deepai-api-key": false, "float-api-key": false, "geocodify-api-key": false,
		"getgeoapi-key": false, "goodday-api-key": false, "html2pdf-api-key": false,
		"humanity-api-key": false, "parseur-api-key": false, "pdflayer-api-key": false,
		"prodpad-api-key": false, "qubole-api-token": false, "ritekit-api-key": false,
		"scrapfly-api-key": false, "screenshotlayer-api-key": false, "spectralops-token": false,
		"timecamp-api-token": false, "voicegain-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestBinaryVerifierRequiresMagicAndSuppressesBody(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "pdf", body: "%PDF-1.7 content", status: VerificationVerified},
		{name: "invalid", body: `{"success":false,"error":{"type":"invalid_access_key"}}`, status: VerificationUnverified},
		{name: "unexpected", body: `<html>error</html>`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyPDFLayer(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestDeBounceVerifierRejectsHTTP200InvalidKey(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"debounce":{"error":"Wrong API","code":"0"},"success":"0"}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyDeBounce(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestHumanityVerifierUsesApplicationStatus(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "valid", body: `{"status":1,"data":{"id":1}}`, status: VerificationVerified},
		{name: "invalid", body: `{"status":3,"data":"Invalid token key - Please re-authenticate","error":"Access token not found in system."}`, status: VerificationUnverified},
		{name: "ambiguous", body: `{"status":3,"data":"Quota exceeded"}`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyHumanity(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestSpectralOpsVerifierRejectsEmpty401(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("Authorization=%q", req.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	result := verifySpectralOps(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEighthVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"chroma-cloud-api-key": false, "convertkit-api-secret": false, "deel-api-token": false,
		"fal-ai-api-key": false, "ilert-api-key": false, "instantly-api-key": false,
		"lithic-api-key": false, "motherduck-token": false, "opticodds-api-key": false,
		"paymongo-secret-key": false, "planhat-api-token": false, "salesflare-api-key": false,
		"scaleway-secret-key": false, "scrutinizer-token": false, "slack-webhook": false,
		"smartlead-api-key": false, "trayio-api-token": false, "triggerdev-api-key": false,
		"trulioo-api-key": false, "unit-api-token": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestSlackWebhookVerifierUsesInvalidPayload(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil || string(body) != `{}` || req.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("body=%q content-type=%q err=%v", body, req.Header.Get("Content-Type"), err)
		}
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("no_text")), Header: make(http.Header)}, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	result := verifySlackWebhook(ctx, "https://hooks.slack.com/services/T1/B1/abcdefghijklmnopqrstuvwxyz")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestUnitVerifierTriesSandbox(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("Authorization=%q", req.Header.Get("Authorization"))
		}
		if req.URL.Host == "api.unit.co" {
			body := `{"errors":[{"title":"Bearer token is invalid or expired"}]}`
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyUnit(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" || requests != 2 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestMotherDuckVerifierRecognizesNonAdminToken(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"code":"FORBIDDEN","message":"Admin access required"}`
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyMotherDuck(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTruliooVerifierUsesDedicatedAuthenticationEndpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v3/connection/testauthentication" || req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("unexpected request: %s %#v", req.URL.Path, req.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`"Hello account"`)), Header: make(http.Header)}, nil
	})}
	result := verifyTrulioo(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestNinthVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"abyssale-api-key": false, "alconost-api-key": false, "apimatic-api-key": false,
		"appointedd-api-key": false, "avaza-api-token": false, "axonaut-api-key": false,
		"buddyns-api-key": false, "bugherd-api-key": false, "diggernaut-api-key": false,
		"groovehq-api-key": false, "helpcrunch-api-key": false, "livestorm-api-key": false,
		"loadmill-api-key": false, "nozbeteams-api-token": false, "overloop-api-key": false,
		"skrapp-api-key": false, "stitchdata-api-token": false, "teletype-api-key": false,
		"upwave-api-key": false, "worksnaps-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestAbyssaleVerifierRecognizesPlanDisabledKey(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.Header.Get("x-api-key") != "secret" {
			t.Fatalf("unexpected request: %s %#v", req.Method, req.Header)
		}
		body := `{"message":"API access is disabled","id":"api_access_denied"}`
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyAbyssale(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTeletypeVerifierRejectsHTTP200InvalidKey(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Auth-Token") != "secret" {
			t.Fatalf("X-Auth-Token=%q", req.Header.Get("X-Auth-Token"))
		}
		body := `{"success":false,"data":null,"errors":[{"code":401,"message":"Your request was made with invalid credentials."}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyTeletype(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestWorksnapsVerifierRequiresProjectsXML(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "valid", body: `<?xml version="1.0"?><projects><project/></projects>`, status: VerificationVerified},
		{name: "unexpected", body: `<html>login</html>`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				username, password, ok := req.BasicAuth()
				if !ok || username != "secret" || password != "ignored" {
					t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyWorksnaps(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestLivestormVerifierUsesAuthenticatedPing(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "secret" || req.URL.Path != "/v1/ping" {
			t.Fatalf("unexpected request: %s %#v", req.URL.Path, req.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":{"type":"ping"}}`)), Header: make(http.Header)}, nil
	})}
	result := verifyLivestorm(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTenthVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"apimetrics-api-key": false, "blazemeter-api-key": false, "chatbot-api-key": false,
		"cloudflare-ca-key": false, "complyadvantage-api-key": false, "courier-api-key": false,
		"cronitor-api-key": false, "feedier-api-key": false, "flexport-api-key": false,
		"juro-api-key": false, "madkudu-api-key": false, "mindmeister-api-token": false,
		"moonclerk-api-key": false, "privacy-api-key": false, "reachmail-api-key": false,
		"sslmate-api-key": false, "storecove-api-key": false, "surveysparrow-api-key": false,
		"survicate-api-key": false, "vyte-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestMindMeisterVerifierRejectsHTTP200OAuthFailure(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("Authorization=%q", req.Header.Get("Authorization"))
		}
		body := `{"rsp":{"stat":"fail","err":{"code":"1010","msg":"The OAuth credentials are invalid."}}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyMindMeister(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestReachMailVerifierRejectsEmpty401(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	result := verifyReachMail(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestComplyAdvantageVerifierTriesRegions(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("Authorization") != "Token secret" {
			t.Fatalf("Authorization=%q", req.Header.Get("Authorization"))
		}
		if req.URL.Host != "api.ap.complyadvantage.com" {
			body := `{"message":"API Key is invalid or was not provided"}`
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"status":"success","content":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyComplyAdvantage(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" || requests != 3 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestCloudflareCAVerifierUsesApplicationStatus(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Auth-User-Service-Key") != "secret" {
			t.Fatalf("X-Auth-User-Service-Key=%q", req.Header.Get("X-Auth-User-Service-Key"))
		}
		body := `{"success":false,"errors":[{"code":9106,"message":"Authentication failed (status: 400)"}],"result":null}`
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyCloudflareCA(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEleventhVerificationMappingBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"aletheia-api-key": false, "allsports-api-key": false, "apacta-api-key": false,
		"appfollow-api-key": false, "calorieninja-api-key": false, "cliengo-api-key": false,
		"dandelion-api-key": false, "docparser-api-key": false, "envoy-api-key": false,
		"finage-api-key": false, "gtmetrix-api-key": false, "hybiscus-api-key": false,
		"interseller-api-key": false, "knapsackpro-api-token": false, "leadfeeder-api-key": false,
		"mailjetsms-api-token": false, "optimizely-api-key": false, "squarespace-api-key": false,
		"tly-api-key": false, "webscraper-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestAllSportsVerifierRejectsHTTP200InvalidKey(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"error":"1","result":[{"param":null,"msg":"Wrong login credentials","cod":1004}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyAllSports(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestAppFollowVerifierRecognizesExhaustedAccount(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-AppFollow-API-Token") != "secret" {
			t.Fatalf("X-AppFollow-API-Token=%q", req.Header.Get("X-AppFollow-API-Token"))
		}
		return &http.Response{StatusCode: http.StatusPaymentRequired, Body: io.NopCloser(strings.NewReader(`{"detail":"Not enough credits"}`)), Header: make(http.Header)}, nil
	})}
	result := verifyAppFollow(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestGTmetrixVerifierRecognizesRestrictedAccount(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "secret" || password != "" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		body := `{"errors":[{"code":"E40300","title":"Account restricted","status":"403"}]}`
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyGTmetrix(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEnvoyVerifierSuppressesLocationResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Api-Key") != "secret" {
			t.Fatalf("X-Api-Key=%q", req.Header.Get("X-Api-Key"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"locations":[{"name":"Private Office"}]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyEnvoy(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestFinalHighConfidenceVerificationBatchIsRegistered(t *testing.T) {
	want := map[string]bool{
		"autopilot-api-key": false, "beebole-api-token": false, "bombbomb-api-key": false,
		"brandfetch-api-key": false, "caflou-api-key": false, "cloverly-api-key": false,
		"ringover-api-key": false, "teachable-api-key": false, "teamwork-token": false,
		"vbout-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestTeamworkVerifierUsesGlobalUserinfo(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "www.teamwork.com" || req.URL.Path != "/launchpad/v1/userinfo.json" || req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("unexpected request: %s %#v", req.URL.String(), req.Header)
		}
		body := `{"sub":"user","user_id":1,"installation_id":2,"url":"https://example.teamwork.com"}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyTeamwork(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBeeboleVerifierUsesReadOnlyRPC(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "secret" || password != "x" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil || string(body) != `{"service":"custom_field.list"}` {
			t.Fatalf("body=%q err=%v", body, err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"result":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyBeebole(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestVBOUTVerifierUsesApplicationStatus(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status VerificationStatus
	}{
		{name: "valid", code: http.StatusOK, body: `{"response":{"header":{"status":"success"},"data":{"id":1}}}`, status: VerificationVerified},
		{name: "invalid", code: http.StatusUnauthorized, body: `{"response":{"header":{"status":"error"},"data":{"errorCode":1000}}}`, status: VerificationUnverified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tt.code, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyVBOUT(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestAdditionalDefensibleVerificationMappingsAreRegistered(t *testing.T) {
	want := map[string]bool{
		"api2cart-api-key": false, "captaindata-api-key": false, "column-api-key": false,
		"insightly-api-key": false, "kylas-api-key": false, "nvapi-key": false,
		"oopspam-api-key": false, "paymo-api-key": false, "tinypng-api-key": false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestAPI2CartVerifierClassifiesApplicationCodes(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status VerificationStatus
	}{
		{name: "valid", body: `{"return_code":0,"result":{"carts_count":0,"carts":[]}}`, status: VerificationVerified},
		{name: "invalid", body: `{"return_code":2,"return_message":"Incorrect API Key","result":{}}`, status: VerificationUnverified},
		{name: "restricted", body: `{"return_code":5,"return_message":"API is restricted","result":{}}`, status: VerificationVerified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifyAPI2Cart(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestInsightlyVerifierTriesRegionalPods(t *testing.T) {
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		username, password, ok := req.BasicAuth()
		if !ok || username != "secret" || password != "" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		if req.URL.Host != "api.eu1.insightly.com" {
			body := `{"Message":"Authorization has been denied for this request."}`
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`[]`)), Header: make(http.Header)}, nil
	})}
	result := verifyInsightly(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" || requests != 3 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestOOPSpamVerifierRejectsExactInvalidCode(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Api-Key") != "secret" {
			t.Fatalf("X-Api-Key=%q", req.Header.Get("X-Api-Key"))
		}
		body := `{"error":{"code":"API_KEY_INVALID","message":"An invalid api_key was supplied"}}`
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := verifyOOPSpam(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationUnverified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestColumnVerifierUsesBlankBasicUsername(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "" || password != "secret" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"entities":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyColumn(WithVerificationHTTPClient(context.Background(), client), "secret")
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSelectPDFVerifierUsesReadOnlyUsageEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status VerificationStatus
	}{
		{name: "valid", code: http.StatusOK, body: `{"status":"active","limit":100,"used":100,"available":0}`, status: VerificationVerified},
		{name: "invalid", code: http.StatusUnauthorized, body: `License key not valid.`, status: VerificationUnverified},
		{name: "ambiguous", code: http.StatusForbidden, body: `Plan does not include usage API`, status: VerificationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api2/usage/" || req.URL.Query().Get("key") != "secret" || req.URL.Query().Get("get_history") != "False" {
					t.Fatalf("unexpected URL: %s", req.URL.String())
				}
				return &http.Response{StatusCode: tt.code, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}
			result := verifySelectPDF(WithVerificationHTTPClient(context.Background(), client), "secret")
			if result.Status != tt.status || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestCompositeVerificationMappingsAreRegistered(t *testing.T) {
	want := map[string]bool{
		"azure-app-config-connection-string":  false,
		"azure-storage-connection-string":     false,
		"gcp-application-default-credentials": false,
		"gcp-service-account-json":            false,
		"mailjet-basic-auth":                  false,
	}
	for _, info := range RegistryInfo(DefaultRegistry()) {
		if _, ok := want[info.ID]; ok {
			want[info.ID] = info.Verifiable
		}
	}
	for id, registered := range want {
		if !registered {
			t.Errorf("%s is not registered with a verifier", id)
		}
	}
}

func TestGCPAuthorizedUserVerifierExchangesAndSuppressesToken(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil || values.Get("grant_type") != "refresh_token" || values.Get("client_id") != "client" || values.Get("client_secret") != "secret+value" || values.Get("refresh_token") != "refresh/value" {
			t.Fatalf("form=%q err=%v", body, err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"sensitive","token_type":"Bearer","expires_in":3600}`)), Header: make(http.Header)}, nil
	})}
	credential := `{"type":"authorized_user","client_id":"client","client_secret":"secret+value","refresh_token":"refresh/value"}`
	result := verifyGCPAuthorizedUser(WithVerificationHTTPClient(context.Background(), client), credential)
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestGCPServiceAccountVerifierSignsAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, key)})
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		values, _ := url.ParseQuery(string(body))
		if values.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(strings.Split(values.Get("assertion"), ".")) != 3 {
			t.Fatalf("unexpected form: %q", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"sensitive","token_type":"Bearer","expires_in":3600}`)), Header: make(http.Header)}, nil
	})}
	credential, _ := json.Marshal(map[string]string{"type": "service_account", "private_key_id": "kid", "private_key": string(keyPEM), "client_email": "test@example.iam.gserviceaccount.com"})
	result := verifyGCPServiceAccount(WithVerificationHTTPClient(context.Background(), client), string(credential))
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestAzureCompositeVerifiersSignRequests(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x01", 64)))
	tests := []struct {
		name       string
		credential string
		verify     Verifier
		authPrefix string
	}{
		{name: "app config", credential: "Endpoint=https://example.azconfig.io;Id=id;Secret=" + key, verify: verifyAzureAppConfiguration, authPrefix: "HMAC-SHA256 Credential=id&"},
		{name: "storage", credential: "DefaultEndpointsProtocol=https;AccountName=example;AccountKey=" + key + ";EndpointSuffix=core.windows.net", verify: verifyAzureStorageConnectionString, authPrefix: "SharedKey example:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if !strings.HasPrefix(req.Header.Get("Authorization"), tt.authPrefix) || req.Header.Get("x-ms-date") == "" {
					t.Fatalf("unexpected headers: %#v", req.Header)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"secret":"private"}`)), Header: make(http.Header)}, nil
			})}
			result := tt.verify(WithVerificationHTTPClient(context.Background(), client), tt.credential)
			if result.Status != VerificationVerified || result.Response != "" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestMailjetBasicVerifierPreservesEncodedCredential(t *testing.T) {
	credential := base64.StdEncoding.EncodeToString([]byte("api-key:private-key"))
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Basic "+credential || req.URL.Query().Get("Limit") != "1" {
			t.Fatalf("unexpected request: %s %#v", req.URL.String(), req.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Count":0,"Data":[]}`)), Header: make(http.Header)}, nil
	})}
	result := verifyMailjetBasicAuth(WithVerificationHTTPClient(context.Background(), client), credential)
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTwilioMultipartCredentialExtractionAndVerification(t *testing.T) {
	input := []byte(`AC0123456789abcdef0123456789abcdef auth_token="0123456789abcdef0123456789abcdef"`)
	var candidate Candidate
	for _, detector := range DefaultRegistry() {
		for _, found := range detector.Detect(input) {
			if found.DetectorID == "twilio-auth-token" {
				candidate = found
			}
		}
	}
	if candidate.Secret != "0123456789abcdef0123456789abcdef" || candidate.SecretParts["account_sid"] != "AC0123456789abcdef0123456789abcdef" || candidate.SecretParts["auth_token"] != candidate.Secret || candidate.CompositeVerifier == nil {
		t.Fatalf("unexpected candidate: %#v", candidate)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		username, password, ok := req.BasicAuth()
		if !ok || username != candidate.SecretParts["account_sid"] || password != candidate.SecretParts["auth_token"] || !strings.Contains(req.URL.Path, username) {
			t.Fatalf("unexpected request: %s username=%q password=%q", req.URL.String(), username, password)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"friendly_name":"private"}`)), Header: make(http.Header)}, nil
	})}
	result := candidate.Verify(WithVerificationHTTPClient(context.Background(), client))
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected result: %#v", result)
	}

	finding := ToFindingAt(candidate, "config.env", "", 1, 1, false)
	legacy := findingFingerprint(candidate.DetectorID, candidate.Secret, "config.env", "")
	if finding.Fingerprint == legacy || finding.LegacyFingerprint != legacy || finding.SecretParts["account_sid"] == "" || finding.RedactedParts["account_sid"] == finding.SecretParts["account_sid"] {
		t.Fatalf("unexpected multipart finding: %#v", finding)
	}
}

func TestAWSCredentialsCorrelateInEitherOrderWithinRecordBoundaries(t *testing.T) {
	accessKeyOne := "AKIAABCDEFGHIJKLMNOP"
	accessKeyTwo := "AKIAQRSTUVWXYZ234567"
	secretOne := strings.Repeat("a", 40)
	secretTwo := strings.Repeat("b", 40)
	input := strings.Join([]string{
		"AWS_ACCESS_KEY_ID=" + accessKeyOne,
		"AWS_SECRET_ACCESS_KEY=" + secretOne,
		"",
		`secret_key: "` + secretTwo + `"`,
		`credential: "` + accessKeyTwo + `"`,
	}, "\n")

	var candidates []Candidate
	for _, detector := range DefaultRegistry() {
		if detector.Info().ID == "aws-credentials" {
			candidates = detector.Detect([]byte(input))
			break
		}
	}
	if len(candidates) != 2 {
		t.Fatalf("expected two correlated AWS credentials, got %#v", candidates)
	}
	if candidates[0].Secret != secretOne || candidates[0].SecretParts["access_key_id"] != accessKeyOne || candidates[0].SecretParts["secret_access_key"] != secretOne {
		t.Fatalf("unexpected first credential: %#v", candidates[0])
	}
	if candidates[1].Secret != secretTwo || candidates[1].SecretParts["access_key_id"] != accessKeyTwo || candidates[1].SecretParts["secret_access_key"] != secretTwo {
		t.Fatalf("unexpected reversed credential: %#v", candidates[1])
	}
}

func TestAWSCredentialsRejectDistantAndCrossRecordFields(t *testing.T) {
	accessKey := "AKIAABCDEFGHIJKLMNOP"
	secret := strings.Repeat("a", 40)
	tests := []string{
		"AWS_ACCESS_KEY_ID=" + accessKey + "\n\nAWS_SECRET_ACCESS_KEY=" + secret,
		"AWS_ACCESS_KEY_ID=" + accessKey + "\n" + strings.Repeat("x", 300) + "\nAWS_SECRET_ACCESS_KEY=" + secret,
	}
	for _, input := range tests {
		for _, detector := range DefaultRegistry() {
			if detector.Info().ID == "aws-credentials" && len(detector.Detect([]byte(input))) != 0 {
				t.Fatalf("correlated fields outside a bounded record: %q", input)
			}
		}
	}
}

func TestAWSCredentialsAttachAndVerifySessionToken(t *testing.T) {
	accessKey := "ASIAABCDEFGHIJKLMNOP"
	secret := strings.Repeat("a", 40)
	sessionToken := strings.Repeat("b", 80)
	input := "AWS_SECRET_ACCESS_KEY=" + secret + "\nAWS_SESSION_TOKEN=" + sessionToken + "\nAWS_ACCESS_KEY_ID=" + accessKey
	var candidate Candidate
	for _, detector := range DefaultRegistry() {
		if detector.Info().ID == "aws-credentials" {
			found := detector.Detect([]byte(input))
			if len(found) != 1 {
				t.Fatalf("expected one temporary credential, got %#v", found)
			}
			candidate = found[0]
			break
		}
	}
	if candidate.SecretParts["session_token"] != sessionToken || candidate.CompositeVerifier == nil {
		t.Fatalf("session token was not correlated: %#v", candidate)
	}

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.Header.Get("Authorization"), "Credential="+accessKey+"/") {
			t.Fatalf("request was not signed with the detected access key: %#v", req.Header)
		}
		if req.Header.Get("X-Amz-Security-Token") != sessionToken {
			t.Fatalf("request omitted the session token: %#v", req.Header)
		}
		body := `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>request-id</RequestId></ResponseMetadata></GetCallerIdentityResponse>`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": []string{"text/xml"}}}, nil
	})}
	result := candidate.Verify(WithVerificationHTTPClient(context.Background(), client))
	if result.Status != VerificationVerified || result.Response != "" {
		t.Fatalf("unexpected verification result: %#v", result)
	}
}

func TestAWSCredentialVerifierClassifiesRejectionAndMissingSession(t *testing.T) {
	candidate := Candidate{SecretParts: map[string]string{
		"access_key_id":     "AKIAABCDEFGHIJKLMNOP",
		"secret_access_key": strings.Repeat("a", 40),
	}}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>rejected</Message></Error><RequestId>request-id</RequestId></ErrorResponse>`
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": []string{"text/xml"}}}, nil
	})}
	result := verifyAWSCredentials(WithVerificationHTTPClient(context.Background(), client), candidate)
	if result.Status != VerificationUnverified || result.ErrorCategory != "invalid_credentials" || result.Response != "" {
		t.Fatalf("unexpected rejection result: %#v", result)
	}

	candidate.SecretParts["access_key_id"] = "ASIAABCDEFGHIJKLMNOP"
	result = verifyAWSCredentials(context.Background(), candidate)
	if result.Status != VerificationUnsupported {
		t.Fatalf("temporary credentials without a session token should be unsupported: %#v", result)
	}
}

func TestMultipartVerificationIdentityIsDeterministic(t *testing.T) {
	verifier := func(context.Context, Candidate) VerificationResult {
		return VerificationResult{Status: VerificationVerified}
	}
	first := Candidate{Secret: "token", SecretParts: map[string]string{"account_sid": "sid", "auth_token": "token"}, CompositeVerifier: verifier}
	second := Candidate{Secret: "token", SecretParts: map[string]string{"auth_token": "token", "account_sid": "sid"}, CompositeVerifier: verifier}
	if first.VerificationCacheKey() != second.VerificationCacheKey() {
		t.Fatal("map insertion order changed multipart verification identity")
	}
	second.SecretParts["account_sid"] = "other"
	if first.VerificationCacheKey() == second.VerificationCacheKey() {
		t.Fatal("different multipart credentials shared verification identity")
	}
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	value, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVerificationProviderFailuresAreUnknown(t *testing.T) {
	cases := []struct {
		status   int
		category string
	}{
		{status: http.StatusTooManyRequests, category: "rate_limited"},
		{status: http.StatusServiceUnavailable, category: "provider"},
		{status: http.StatusForbidden, category: "authorization"},
	}
	for _, tc := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }))
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		result := verifyHTTPRequest(context.Background(), req)
		server.Close()
		if result.Status != VerificationUnknown || result.ErrorCategory != tc.category {
			t.Fatalf("status %d result=%#v", tc.status, result)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	result := verifyHTTPRequest(ctx, req)
	if result.Status != VerificationUnknown || result.ErrorCategory != "timeout" {
		t.Fatalf("timeout result=%#v", result)
	}
}

func TestDefaultRegistryFindsGitHubToken(t *testing.T) {
	input := []byte("token := \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"")
	var found bool
	for _, d := range DefaultRegistry() {
		for _, c := range d.Detect(input) {
			if c.DetectorID == "github-token" {
				found = true
				if c.Secret != "ghp_abcdefghijklmnopqrstuvwxyz0123456789" {
					t.Fatalf("unexpected secret: %q", c.Secret)
				}
			}
		}
	}
	if !found {
		t.Fatal("expected github-token finding")
	}
}

func TestDefaultRegistryFindsExpandedParityTokens(t *testing.T) {
	cases := []struct {
		id     string
		input  string
		secret string
	}{
		{"azure-devops-pat", strings.Repeat("a", 75) + "AZDO" + strings.Repeat("b", 5), strings.Repeat("a", 75) + "AZDO" + strings.Repeat("b", 5)},
		{"terraform-cloud-token", strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("A", 67), strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("A", 67)},
		{"netlify-token", "nfp_" + strings.Repeat("A", 40), "nfp_" + strings.Repeat("A", 40)},
		{"pulumi-token", "pul-" + strings.Repeat("a", 40), "pul-" + strings.Repeat("a", 40)},
		{"doppler-token", "dp.st." + strings.Repeat("A", 40), "dp.st." + strings.Repeat("A", 40)},
		{"tailscale-key", "tskey-api-" + strings.Repeat("A", 32), "tskey-api-" + strings.Repeat("A", 32)},
		{"ngrok-token", "ngrok_api_" + strings.Repeat("A", 32), "ngrok_api_" + strings.Repeat("A", 32)},
		{"buildkite-token", "bkua_" + strings.Repeat("a", 40), "bkua_" + strings.Repeat("a", 40)},
		{"nuget-api-key", "oy2" + strings.Repeat("a", 43), "oy2" + strings.Repeat("a", 43)},
		{"rubygems-api-key", "rubygems_" + strings.Repeat("a", 48), "rubygems_" + strings.Repeat("a", 48)},
		{"slack-webhook", "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvw", "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvw"},
		{"discord-webhook", "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("A", 68), "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("A", 68)},
		{"microsoft-teams-webhook", "https://example.webhook.office.com/webhookb2/11111111-2222-3333-4444-555555555555@aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/IncomingWebhook/0123456789abcdef0123456789abcdef/99999999-8888-7777-6666-555555555555", "https://example.webhook.office.com/webhookb2/11111111-2222-3333-4444-555555555555@aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/IncomingWebhook/0123456789abcdef0123456789abcdef/99999999-8888-7777-6666-555555555555"},
		{"grafana-token", "glc_eyJ" + strings.Repeat("A", 80), "glc_eyJ" + strings.Repeat("A", 80)},
		{"grafana-service-account-token", "glsa_" + strings.Repeat("A", 41), "glsa_" + strings.Repeat("A", 41)},
		{"sentry-user-token", "sntryu_" + strings.Repeat("a", 64), "sntryu_" + strings.Repeat("a", 64)},
		{"sentry-org-token", "sntrys_eyJ" + strings.Repeat("A", 197), "sntrys_eyJ" + strings.Repeat("A", 197)},
		{"honeycomb-api-key", "HONEYCOMB_API_KEY=" + strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{"opsgenie-api-key", "OPSGENIE_API_KEY=123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000"},
		{"splunk-observability-token", "X-Sf-Token: AbCdEfGhIjKlMnOpQrSt12", "AbCdEfGhIjKlMnOpQrSt12"},
		{"webex-bot-token", "webex " + strings.Repeat("A", 64) + "_AB12_12345678-1234-1234-1234-123456789abc", strings.Repeat("A", 64) + "_AB12_12345678-1234-1234-1234-123456789abc"},
		{"huggingface-token", "hf_" + strings.Repeat("A", 34), "hf_" + strings.Repeat("A", 34)},
		{"groq-api-key", "gsk_" + strings.Repeat("A", 52), "gsk_" + strings.Repeat("A", 52)},
		{"replicate-token", "r8_" + strings.Repeat("A", 40), "r8_" + strings.Repeat("A", 40)},
		{"airtable-pat", "patAbC123dEf4567X." + strings.Repeat("a", 64), "patAbC123dEf4567X." + strings.Repeat("a", 64)},
		{"airtable-oauth-client-secret", "airtable oauth client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"asana-pat", "asana 123/1234567890123456/9876543210987654:abcdefghijklmnopqrstuvwxyzABCDEF123456", "123/1234567890123456/9876543210987654:abcdefghijklmnopqrstuvwxyzABCDEF123456"},
		{"asana-oauth-client-secret", "asana oauth client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"anypoint-oauth-client-secret", "mulesoft anypoint client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clickup-token", "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
		{"typeform-token", "tfp_" + strings.Repeat("A", 44), "tfp_" + strings.Repeat("A", 44)},
		{"hubspot-private-app-token", "pat-na1-12345678-1234-1234-1234-123456789abc", "pat-na1-12345678-1234-1234-1234-123456789abc"},
		{"mailchimp-key", strings.Repeat("a", 32) + "-us12", strings.Repeat("a", 32) + "-us12"},
		{"klaviyo-key", "klaviyo pk_" + strings.Repeat("a", 34), "pk_" + strings.Repeat("a", 34)},
		{"braze-api-key", "rest.iad-01.braze.com BRAZE_API_KEY=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"iterable-api-key", "api.iterable.com iterable_api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"activecampaign-api-token", "activecampaign Api-Token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"marketo-client-secret", "mktorest.com marketo_client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tiktok-business-api-secret", "business-api.tiktok.com Access-Token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"linkedin-client-secret", "api.linkedin.com linkedin_client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sfmc-client-secret", "auth.marketingcloudapis.com SFMC_CLIENT_SECRET=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"google-ads-developer-token", "google-ads.yaml developer-token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"branch-secret", "api2.branch.io branch_secret=\"secret_" + strings.Repeat("A", 32) + "\"", "secret_" + strings.Repeat("A", 32)},
		{"appsflyer-api-token", "api.appsflyer.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"adjust-api-token", "api.adjust.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"attentive-api-key", "api.attentivemobile.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"razorpay-key", "rzp_live_AbCdEf12345678", "rzp_live_AbCdEf12345678"},
		{"nightfall-api-key", "NF-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6", "NF-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"},
		{"endorlabs-token", "endr+AbCdEfGhIjKlMn12", "endr+AbCdEfGhIjKlMn12"},
		{"trufflehog-enterprise-key", "thog-key-0123456789abcdef", "thog-key-0123456789abcdef"},
		{"trufflehog-enterprise-secret", "thog-secret-0123456789abcdef0123456789abcdef", "thog-secret-0123456789abcdef0123456789abcdef"},
		{"tines-webhook", "https://acme.tines.com/webhook/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210", "https://acme.tines.com/webhook/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210"},
		{"pinecone-api-key", "pcsk_abc12_" + strings.Repeat("A", 63), "pcsk_abc12_" + strings.Repeat("A", 63)},
		{"langsmith-api-key", "lsv2_pt_" + strings.Repeat("a", 32) + "_" + strings.Repeat("b", 10), "lsv2_pt_" + strings.Repeat("a", 32) + "_" + strings.Repeat("b", 10)},
		{"langfuse-secret-key", "sk-lf-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "sk-lf-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"elevenlabs-api-key", "elevenlabs sk_" + strings.Repeat("a", 48), "sk_" + strings.Repeat("a", 48)},
		{"xai-api-key", "xai-" + strings.Repeat("A", 80), "xai-" + strings.Repeat("A", 80)},
		{"cohere-api-key", "api.cohere.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mistral-api-key", "api.mistral.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"togetherai-api-key", "api.together.xyz api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fireworksai-api-key", "api.fireworks.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"voyageai-api-key", "api.voyageai.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"perplexity-api-key", "api.perplexity.ai api_key=\"pplx-" + strings.Repeat("A", 48) + "\"", "pplx-" + strings.Repeat("A", 48)},
		{"openrouter-api-key", "openrouter.ai api_key=\"sk-or-" + strings.Repeat("A", 48) + "\"", "sk-or-" + strings.Repeat("A", 48)},
		{"ai21-api-key", "api.ai21.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cerebras-api-key", "api.cerebras.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"baseten-api-key", "model-apis.baseten.co api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"runpod-api-key", "api.runpod.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"modal-api-token", "api.modal.com token_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fal-ai-api-key", "api.fal.ai api_key=\"12345678-1234-1234-1234-123456789abc:" + strings.Repeat("A", 32) + "\"", "12345678-1234-1234-1234-123456789abc:" + strings.Repeat("A", 32)},
		{"novita-api-key", "api.novita.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"predibase-api-token", "serving.app.predibase.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"octoai-api-token", "api.octoai.cloud api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"qdrant-api-key", "cloud.qdrant.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"weaviate-api-key", "weaviate.cloud api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zilliz-api-key", "api.cloud.zilliz.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"chroma-cloud-api-key", "api.trychroma.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"voiceflow-api-key", "VF.DM." + strings.Repeat("a", 24) + "." + strings.Repeat("A", 16), "VF.DM." + strings.Repeat("a", 24) + "." + strings.Repeat("A", 16)},
		{"harness-pat", "harness pat." + strings.Repeat("A", 22) + "." + strings.Repeat("a", 24) + "." + strings.Repeat("B", 20), "pat." + strings.Repeat("A", 22) + "." + strings.Repeat("a", 24) + "." + strings.Repeat("B", 20)},
		{"resend-api-key", "RESEND_API_KEY=\"re_" + strings.Repeat("A", 32) + "\"", "re_" + strings.Repeat("A", 32)},
		{"clerk-secret-key", "CLERK_SECRET_KEY=\"sk_live_" + strings.Repeat("A", 32) + "\"", "sk_live_" + strings.Repeat("A", 32)},
		{"workos-api-key", "WORKOS_API_KEY=\"sk_test_" + strings.Repeat("B", 32) + "\"", "sk_test_" + strings.Repeat("B", 32)},
		{"liveblocks-secret-key", "LIVEBLOCKS_SECRET_KEY=\"sk_prod_" + strings.Repeat("C", 32) + "\"", "sk_prod_" + strings.Repeat("C", 32)},
		{"polar-access-token", "polar_oat_" + strings.Repeat("D", 32), "polar_oat_" + strings.Repeat("D", 32)},
		{"supabase-secret-key", "sb_secret_" + strings.Repeat("E", 32), "sb_secret_" + strings.Repeat("E", 32)},
		{"webhook-signing-secret", "whsec_" + strings.Repeat("F", 32), "whsec_" + strings.Repeat("F", 32)},
		{"zoho-crm-token", "1000." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32), "1000." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32)},
		{"intercom-access-token", "intercom_token=\"dG9rO" + strings.Repeat("A", 54) + "=\"", "dG9rO" + strings.Repeat("A", 54) + "="},
		{"front-api-token", "front_token=\"" + strings.Repeat("A", 36) + "." + strings.Repeat("B", 188) + "\"", strings.Repeat("A", 36) + "." + strings.Repeat("B", 188)},
		{"segment-api-key", "segment_key=\"" + strings.Repeat("A", 43) + "." + strings.Repeat("B", 43) + "\"", strings.Repeat("A", 43) + "." + strings.Repeat("B", 43)},
		{"posthog-personal-api-key", "phx_" + strings.Repeat("A", 43), "phx_" + strings.Repeat("A", 43)},
		{"launchdarkly-key", "api-123e4567-e89b-42d3-a456-426614174000", "api-123e4567-e89b-42d3-a456-426614174000"},
		{"postmark-token", "postmark_token=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"coda-api-token", "coda_api_key=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"calendly-api-key", "calendly_token=\"eyJ" + strings.Repeat("A", 120) + ".eyJ" + strings.Repeat("B", 120) + "." + strings.Repeat("C", 40) + "\"", "eyJ" + strings.Repeat("A", 120) + ".eyJ" + strings.Repeat("B", 120) + "." + strings.Repeat("C", 40)},
		{"monday-api-token", "monday_token=\"eyJ" + strings.Repeat("A", 30) + ".eyJ" + strings.Repeat("B", 150) + "." + strings.Repeat("C", 40) + "\"", "eyJ" + strings.Repeat("A", 30) + ".eyJ" + strings.Repeat("B", 150) + "." + strings.Repeat("C", 40)},
		{"flyio-token", "FlyV1 fm1_" + strings.Repeat("A", 520), "FlyV1 fm1_" + strings.Repeat("A", 520)},
		{"cloudflare-ca-key", "cloudflare v1.0-" + strings.Repeat("A", 171), "v1.0-" + strings.Repeat("A", 171)},
		{"artifactory-access-token", "AKCp" + strings.Repeat("A", 69), "AKCp" + strings.Repeat("A", 69)},
		{"artifactory-reference-token", "cmVmdGtu" + strings.Repeat("A", 56), "cmVmdGtu" + strings.Repeat("A", 56)},
		{"azure-app-config-connection-string", "Endpoint=https://demo-app.azconfig.io;Id=AbCdEfGhIjKlMnOpQrStUv==;Secret=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==", "Endpoint=https://demo-app.azconfig.io;Id=AbCdEfGhIjKlMnOpQrStUv==;Secret=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=="},
		{"azure-storage-connection-string", "DefaultEndpointsProtocol=https;AccountName=prodstorageacct;AccountKey=" + strings.Repeat("A", 86) + "==;EndpointSuffix=core.windows.net", "DefaultEndpointsProtocol=https;AccountName=prodstorageacct;AccountKey=" + strings.Repeat("A", 86) + "==;EndpointSuffix=core.windows.net"},
		{"azure-cosmosdb-connection-string", "AccountEndpoint=https://prod-cosmos.documents.azure.com:443/;AccountKey=" + strings.Repeat("A", 86) + "==;", "AccountEndpoint=https://prod-cosmos.documents.azure.com:443/;AccountKey=" + strings.Repeat("A", 86) + "==;"},
		{"azure-sas-url", "https://prodstorage.blob.core.windows.net/container/blob.txt?sp=r&st=2026-01-01T00:00:00Z&se=2026-12-31T23:59:59Z&spr=https&sv=2024-01-01&sr=b&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2B", "https://prodstorage.blob.core.windows.net/container/blob.txt?sp=r&st=2026-01-01T00:00:00Z&se=2026-12-31T23:59:59Z&spr=https&sv=2024-01-01&sr=b&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2B"},
		{"azure-function-key-url", "https://demo-func.azurewebsites.net/api/process?code=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-"},
		{"spectralops-token", "spu-a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6", "spu-a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6"},
		{"atlassian-api-token", "ATCTT3xFfG" + strings.Repeat("A", 64) + "=12345678", "ATCTT3xFfG" + strings.Repeat("A", 64) + "=12345678"},
		{"jira-api-token", "ATATT" + strings.Repeat("A", 64) + "=12345678", "ATATT" + strings.Repeat("A", 64) + "=12345678"},
		{"salesforce-access-token", "salesforce 00D000000000001!" + strings.Repeat("A", 96), "00D000000000001!" + strings.Repeat("A", 96)},
		{"salesforce-refresh-token", "5AEP861" + strings.Repeat("A", 80), "5AEP861" + strings.Repeat("A", 80)},
		{"salesforce-consumer-key", "3MVG9" + strings.Repeat("A", 80), "3MVG9" + strings.Repeat("A", 80)},
		{"twilio-auth-token", "AC0123456789abcdef0123456789abcdef auth_token=\"0123456789abcdef0123456789abcdef\"", "0123456789abcdef0123456789abcdef"},
		{"openphone-api-key", "api.openphone.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aircall-api-token", "api.aircall.io api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dialpad-api-key", "dialpad.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"five9-api-secret", "five9.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"genesys-cloud-client-secret", "api.mypurecloud.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"talkdesk-api-token", "api.talkdeskapp.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ringover-api-key", "api.ringover.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"justcall-api-key", "api.justcall.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"callrail-api-key", "api.callrail.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"calltrackingmetrics-api-key", "api.calltrackingmetrics.com api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mailjet-basic-auth", "mailjet basic auth " + strings.Repeat("A", 87) + "=", strings.Repeat("A", 87) + "="},
		{"okta-api-token", "tenant.okta.com token = 00abcdefghijklmnopqrstuvwxyz0123456789ABCD", "00abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
		{"urlscan-api-key", "urlscan api_key = 123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000"},
		{"openai-admin-key", "sk-admin-" + strings.Repeat("A", 58) + "T3BlbkFJ" + strings.Repeat("B", 58), "sk-admin-" + strings.Repeat("A", 58) + "T3BlbkFJ" + strings.Repeat("B", 58)},
		{"deepseek-api-key", "DEEPSEEK_API_KEY=\"sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\"", "sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		{"weightsandbiases-api-key", "WANDB_API_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"assemblyai-api-key", "ASSEMBLYAI_API_KEY=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"deepgram-api-key", "DEEPGRAM_API_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"edenai-api-key", "EDENAI_API_KEY=\"" + strings.Repeat("A", 36) + "." + strings.Repeat("B", 92) + "." + strings.Repeat("C", 43) + "\"", strings.Repeat("A", 36) + "." + strings.Repeat("B", 92) + "." + strings.Repeat("C", 43)},
		{"monkeylearn-api-key", "MONKEYLEARN_API_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"contentful-pat", "CFPAT-" + strings.Repeat("a", 43), "CFPAT-" + strings.Repeat("a", 43)},
		{"storyblok-personal-access-token", "storyblok_token=\"" + strings.Repeat("A", 22) + "tt-123456-" + strings.Repeat("B", 20) + "\"", strings.Repeat("A", 22) + "tt-123456-" + strings.Repeat("B", 20)},
		{"storyblok-access-token", "storyblok_access=\"" + strings.Repeat("A", 22) + "tt\"", strings.Repeat("A", 22) + "tt"},
		{"sanity-auth-token", "sanity_token=\"sk" + strings.Repeat("A", 79) + "\"", "sk" + strings.Repeat("A", 79)},
		{"contentstack-api-key", "cdn.contentstack.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"datocms-api-token", "site-api.datocms.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"directus-api-token", "directus.cloud static_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"strapi-api-token", "strapi.io api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"prismic-api-token", "repo.cdn.prismic.io access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"builderio-private-key", "cdn.builder.io private_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"commercetools-client-secret", "auth.us-central1.gcp.commercetools.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bigcommerce-api-token", "api.bigcommerce.com x-auth-token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"saleor-api-token", "saleor.cloud app_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"medusa-api-token", "medusajs admin_api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"elastic-email-api-key", "elasticemail_api_key=\"" + strings.Repeat("A", 96) + "\"", strings.Repeat("A", 96)},
		{"shortcut-api-token", "shortcut_token=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"webflow-api-key", "webflow_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"mapbox-secret-token", "mapbox_token=\"sk." + strings.Repeat("A", 90) + "\"", "sk." + strings.Repeat("A", 90)},
		{"locationiq-api-key", "locationiq_key=\"pk." + strings.Repeat("A", 32) + "\"", "pk." + strings.Repeat("A", 32)},
		{"coinapi-key", "X-CoinAPI-Key: ABCD1234-EF56-7890-ABCD-1234567890AB", "ABCD1234-EF56-7890-ABCD-1234567890AB"},
		{"onfido-api-token", "ONFIDO_API_TOKEN=api_live_us." + strings.Repeat("A", 48), "api_live_us." + strings.Repeat("A", 48)},
		{"sumsub-app-token", "api.sumsub.com X-App-Token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"modern-treasury-api-key", "modern treasury api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"treasury-prime-api-secret", "treasury prime api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"unit-api-token", "api.unit.co api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"increase-api-key", "api.increase.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"lithic-api-key", "api.lithic.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"marqeta-api-token", "sandbox-api.marqeta.com application_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"adyen-api-key", "adyen ws_123456@Company.Example api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"persona-api-key", "api.withpersona.com persona_api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fireblocks-api-key", "fireblocks X-API-Key=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"alpaca-api-secret", "paper-api.alpaca.markets APCA-API-SECRET-KEY=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sportradar-api-key", "api.sportradar.com x-api-key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"apisports-api-key", "v3.football.api-sports.io x-apisports-key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"databet-secret", "feed.int.databet.cloud widget_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"betfair-api-token", "api.betfair.com/exchange X-Application=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"oddsjam-api-key", "api.oddsjam.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"opticodds-api-key", "api.opticodds.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"geocomply-license-key", "geocomply license_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"alloy-api-key", "developer.alloy.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"socure-api-key", "api.socure.com X-API-Key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"complyadvantage-api-key", "api.complyadvantage.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"chainalysis-api-key", "api.chainalysis.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"trm-labs-api-key", "api.trmlabs.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bitgo-access-token", "app.bitgo.com access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"circle-api-key", "api.circle.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"drivewealth-client-secret", "bo-api.drivewealth client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"teller-signing-secret", "api.teller.io signing_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"truelayer-client-secret", "auth.truelayer.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"yapily-application-secret", "api.yapily.com application_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tink-client-secret", "oauth.tink.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"seon-api-key", "api.seon.io X-API-Key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"jumio-client-secret", "api.jumio.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"trulioo-api-key", "api.trulioo.com bearer=\"eyJ" + strings.Repeat("A", 20) + ".eyJ" + strings.Repeat("A", 20) + "." + strings.Repeat("A", 20) + "\"", "eyJ" + strings.Repeat("A", 20) + ".eyJ" + strings.Repeat("A", 20) + "." + strings.Repeat("A", 20)},
		{"sardine-client-secret", "api.sardine.ai client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sift-api-key", "api.sift.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"forter-api-key", "api.forter.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"riskified-api-key", "api.riskified.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"etherscan-api-key", "etherscan apikey " + strings.Repeat("A", 34), strings.Repeat("A", 34)},
		{"bscscan-api-key", "bscscan apikey " + strings.Repeat("B", 34), strings.Repeat("B", 34)},
		{"guardian-api-key", "content.guardianapis.com api-key 12345678-abcd-1234-abcd-123456789abc", "12345678-abcd-1234-abcd-123456789abc"},
		{"circleci-pat", "CCIPAT_" + strings.Repeat("A", 22) + "_" + strings.Repeat("a", 40), "CCIPAT_" + strings.Repeat("A", 22) + "_" + strings.Repeat("a", 40)},
		{"sourcegraph-token", "sgp_0123456789abcdef_" + strings.Repeat("a", 40), "sgp_0123456789abcdef_" + strings.Repeat("a", 40)},
		{"sourcegraph-cody-token", "slk_" + strings.Repeat("a", 64), "slk_" + strings.Repeat("a", 64)},
		{"snyk-api-key", "SNYK_TOKEN=\"00000000-0000-4000-8000-000000000000\"", "00000000-0000-4000-8000-000000000000"},
		{"uptimerobot-api-key", "UPTIMEROBOT_API_KEY=\"FAKE12345-FAKE12345678901234567890\"", "FAKE12345-FAKE12345678901234567890"},
		{"sumologic-access-id", "sumologic access_id=\"suFAKE12345678\"", "suFAKE12345678"},
		{"sumologic-access-key", "sumologic access_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"statuspage-api-key", "statuspage token=\"00000000-0000-4000-8000-000000000000\"", "00000000-0000-4000-8000-000000000000"},
		{"sendinblue-api-key", "xkeysib-" + strings.Repeat("A", 81), "xkeysib-" + strings.Repeat("A", 81)},
		{"teamwork-token", "tkn.v1_" + strings.Repeat("A", 71) + "=", "tkn.v1_" + strings.Repeat("A", 71) + "="},
		{"salesblink-api-key", "salesblink_api_key=\"key-" + strings.Repeat("A", 64) + "\"", "key-" + strings.Repeat("A", 64)},
		{"smooch-app-key", "smooch_app_key=\"act_" + strings.Repeat("a", 24) + "\"", "act_" + strings.Repeat("a", 24)},
		{"mailmodo-api-key", "mailmodo_key=\"AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD\"", "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD"},
		{"zapier-webhook", "https://hooks.zapier.com/hooks/catch/ABCDEF12/GHIJKLM", "https://hooks.zapier.com/hooks/catch/ABCDEF12/GHIJKLM"},
		{"inngest-signing-key", "api.inngest.com signing_key=\"signkey-" + strings.Repeat("A", 48) + "\"", "signkey-" + strings.Repeat("A", 48)},
		{"triggerdev-api-key", "api.trigger.dev api_key=\"tr_dev_" + strings.Repeat("A", 48) + "\"", "tr_dev_" + strings.Repeat("A", 48)},
		{"temporal-cloud-api-key", "cloud.temporal.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"windmill-api-token", "app.windmill.dev api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"n8n-api-key", "n8n.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"workato-api-token", "apim.workato.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"trayio-api-token", "api.tray.io api_token=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"airbyte-api-token", "api.airbyte.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fivetran-api-secret", "api.fivetran.com api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"hightouch-api-key", "api.hightouch.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"deno-deploy-token", "ddp_" + strings.Repeat("A", 36), "ddp_" + strings.Repeat("A", 36)},
		{"supabase-management-token", "sbp_" + strings.Repeat("a", 40), "sbp_" + strings.Repeat("a", 40)},
		{"prefect-api-key", "pnu_" + strings.Repeat("A", 36), "pnu_" + strings.Repeat("A", 36)},
		{"figma-pat", "figd_" + strings.Repeat("A", 40), "figd_" + strings.Repeat("A", 40)},
		{"saladcloud-api-key", "salad_cloud_abc1234_" + strings.Repeat("A", 28), "salad_cloud_abc1234_" + strings.Repeat("A", 28)},
		{"planetscale-token", "pscale_tkn_" + strings.Repeat("A", 43), "pscale_tkn_" + strings.Repeat("A", 43)},
		{"planetscale-db-password", "pscale_pw_" + strings.Repeat("A", 43), "pscale_pw_" + strings.Repeat("A", 43)},
		{"databricks-token", "databricks dapi" + strings.Repeat("a", 32), "dapi" + strings.Repeat("a", 32)},
		{"neon-api-key", "api.neon.tech api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"turso-api-token", "api.turso.tech auth_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"xata-api-key", "api.xata.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cockroachcloud-api-key", "api.cockroachlabs.cloud api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"upstash-token", "api.upstash.com rest_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"motherduck-token", "motherduck.com token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"grafbase-api-key", "api.grafbase.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"singlestore-api-key", "api.singlestore.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"timescale-api-key", "api.timescale.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"convex-deploy-key", "api.convex.dev deploy_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"portainer-token", "portainertoken=ptr_" + strings.Repeat("A", 32), "ptr_" + strings.Repeat("A", 32)},
		{"ftp-credential-url", "sftp://deploy:Sup3rSecretPass@sftp.example.com/releases", "sftp://deploy:Sup3rSecretPass@sftp.example.com/releases"},
		{"box-client-secret", `{"boxAppSettings":{"clientID":"abc","clientSecret":"` + strings.Repeat("A", 48) + `"}}`, strings.Repeat("A", 48)},
		{"shopify-oauth-client-secret", "shopify oauth client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aws-appsync-api-key", "https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql api_key=da2-abcdefghijklmnopqrstuvwxyz", "da2-abcdefghijklmnopqrstuvwxyz"},
		{"azure-openai-key", "https://demo.openai.azure.com api-key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"azure-batch-key", "https://acct.region.batch.azure.com key=" + strings.Repeat("A", 88), strings.Repeat("A", 88)},
		{"azure-container-registry-password", "myregistry.azurecr.io " + strings.Repeat("a", 42) + "+ACRbbbbbb", strings.Repeat("a", 42) + "+ACRbbbbbb"},
		{"gcp-service-account-json", `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n","client_email":"fake@proj.iam.gserviceaccount.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs"}`, `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n","client_email":"fake@proj.iam.gserviceaccount.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs"}`},
		{"gcp-application-default-credentials", `{"client_id":"fake.apps.googleusercontent.com","client_secret":"` + strings.Repeat("A", 24) + `","refresh_token":"` + strings.Repeat("B", 32) + `"}`, `{"client_id":"fake.apps.googleusercontent.com","client_secret":"` + strings.Repeat("A", 24) + `","refresh_token":"` + strings.Repeat("B", 32) + `"}`},
		{"redis-uri", "rediss://default:FakeRedisPass123@example.redis.cache.windows.net:6380", "rediss://default:FakeRedisPass123@example.redis.cache.windows.net:6380"},
		{"azure-redis-connection-string", "demo.redis.cache.windows.net:6380,password=" + strings.Repeat("A", 44) + ",ssl=True,abortConnect=False", "demo.redis.cache.windows.net:6380,password=" + strings.Repeat("A", 44) + ",ssl=True,abortConnect=False"},
		{"couchbase-capella-uri", "couchbases://user:Passw0rd!@cb.abc123.cloud.couchbase.com", "couchbases://user:Passw0rd!@cb.abc123.cloud.couchbase.com"},
		{"closecrm-api-key", "api_" + strings.Repeat("A", 45), "api_" + strings.Repeat("A", 45)},
		{"paystack-secret-key", "sk_test_" + strings.Repeat("A", 40), "sk_test_" + strings.Repeat("A", 40)},
		{"wrike-access-token", "wrike token ey" + strings.Repeat("A", 333), "ey" + strings.Repeat("A", 333)},
		{"twitter-consumer-secret", "twitter consumer_secret " + strings.Repeat("A", 50), strings.Repeat("A", 50)},
		{"facebook-oauth-secret", "facebook app_secret " + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"flutterwave-secret-key", "FLWSECK-0123456789abcdef0123456789abcdef-X", "FLWSECK-0123456789abcdef0123456789abcdef-X"},
		{"pagarme-live-key", "ak_live_0123456789abcdefghijklmnopqrst", "ak_live_0123456789abcdefghijklmnopqrst"},
		{"rechargepayments-token", "sk_1x1_" + strings.Repeat("a", 64), "sk_1x1_" + strings.Repeat("a", 64)},
		{"lemonsqueezy-api-token", "lemonsqueezy token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + strings.Repeat("A", 314) + "." + strings.Repeat("B", 512), "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + strings.Repeat("A", 314) + "." + strings.Repeat("B", 512)},
		{"plaid-access-token", "access-sandbox-01234567-89ab-cdef-0123-456789abcdef", "access-sandbox-01234567-89ab-cdef-0123-456789abcdef"},
		{"plaid-client-secret", "plaid PLAID_SECRET=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cloudinary-url", "cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz1@demo-cloud", "cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz1@demo-cloud"},
		{"zendesk-api-token", "acme.zendesk.com ZENDESK_API_TOKEN=" + strings.Repeat("A", 40), strings.Repeat("A", 40)},
		{"freshdesk-api-key", "acme.freshdesk.com FRESHDESK_API_KEY=a1B2c3D4e5F6g7H8i9J0", "a1B2c3D4e5F6g7H8i9J0"},
		{"helpcrunch-api-key", "HELPCRUNCH_TOKEN=" + strings.Repeat("A", 328), strings.Repeat("A", 328)},
		{"line-messaging-token", "LINE_MESSAGING_TOKEN=" + strings.Repeat("A", 172), strings.Repeat("A", 172)},
		{"courier-api-key", "COURIER_AUTH_TOKEN=pk_live_" + strings.Repeat("A", 28), "pk_live_" + strings.Repeat("A", 28)},
		{"moengage-api-secret", "api.moengage.com api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clevertap-passcode", "api.clevertap.com passcode=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mparticle-api-secret", "s2s.mparticle.com api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"hashicorp-vault-approle", "vault role_id=11111111-2222-3333-4444-555555555555 secret_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"mattermost-personal-token", "mattermost token abc123def456ghi789jkl012mn team.cloud.mattermost.com", "abc123def456ghi789jkl012mn"},
		{"cloudflare-global-api-key", "cloudflare global_api_key=0123456789abcdef0123456789abcdef01234", "0123456789abcdef0123456789abcdef01234"},
		{"docker-auth-config", `{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXQxMjM0NTY3ODkw"}}}`, `"auths":{"ghcr.io":{"auth":"dXNlcjpwYXQxMjM0NTY3ODkw"`},
		{"azure-search-key", "https://acme.search.windows.net api-key: " + strings.Repeat("A", 52), strings.Repeat("A", 52)},
		{"azure-apim-subscription-key", "Ocp-Apim-Subscription-Key: 0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"azure-direct-management-key", "directline.botframework.com direct_line_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bing-subscription-key", "https://api.bing.microsoft.com/v7.0/search subscription_key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"auth0-domain-jwt", "tenant.auth0.com token=eyJ" + strings.Repeat("A", 24) + ".eyJ" + strings.Repeat("B", 24) + "." + strings.Repeat("C", 24), "eyJ" + strings.Repeat("A", 24) + ".eyJ" + strings.Repeat("B", 24) + "." + strings.Repeat("C", 24)},
		{"virustotal-api-key", "virustotal_api_key=" + strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"shodan-api-key", "SHODAN_API_KEY=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"securitytrails-api-key", "securitytrails_key=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"snowflake-url", "snowflake://svc:Sup3rSecret@xy12345.us-east-1/db", "snowflake://svc:Sup3rSecret@xy12345.us-east-1/db"},
		{"sqlserver-connection-string", "Server=tcp:x.database.windows.net;User ID=app;Password=P@ssw0rd123;", "Server=tcp:x.database.windows.net;User ID=app;Password=P@ssw0rd123;"},
		{"rabbitmq-uri", "amqps://user:VerySecret123@mq.example/vhost", "amqps://user:VerySecret123@mq.example/vhost"},
		{"newsapi-key", "newsapi_key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"openweather-api-key", "openweather APPID=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"tomorrowio-api-key", "tomorrow.io apikey=AbCdEfGhIjKlMnOpQrStUvWxYz123456", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"},
		{"here-api-key", "platform.here.com apiKey " + strings.Repeat("A", 43), strings.Repeat("A", 43)},
		{"polygon-api-key", "POLYGON_API_KEY=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"aws-session-token", "aws_session_token=\"" + strings.Repeat("A", 120) + "\"", strings.Repeat("A", 120)},
		{"alibaba-access-key", "alibaba access_key=LTAI" + strings.Repeat("A", 20), "LTAI" + strings.Repeat("A", 20)},
		{"scaleway-secret-key", "SCW_SECRET_KEY=11111111-2222-3333-4444-555555555555", "11111111-2222-3333-4444-555555555555"},
		{"github-oauth-client-secret", "github_oauth client_secret=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"github-app-private-key", "github_app_private_key = -----BEGIN PRIVATE KEY-----\nFAKEKEYDATA\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\nFAKEKEYDATA\n-----END PRIVATE KEY-----"},
		{"gitlab-oauth-client-secret", "gitlab_oauth client_secret=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"datadog-app-key", "DD_APP_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"braintree-access-token", "access_token$production$merchantid$" + strings.Repeat("A", 32), "access_token$production$merchantid$" + strings.Repeat("A", 32)},
		{"coinbase-cdp-api-key", "coinbase key=organizations/11111111-2222-3333-4444-555555555555/apiKeys/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "organizations/11111111-2222-3333-4444-555555555555/apiKeys/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"coinbase-exchange-secret", "api.exchange.coinbase.com CB-ACCESS-SECRET=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"webex-access-token", "webex access_token=" + strings.Repeat("A", 64) + "_AB12_11111111-2222-3333-4444-555555555555", strings.Repeat("A", 64) + "_AB12_11111111-2222-3333-4444-555555555555"},
		{"auth0-client-secret", "auth0 client_secret=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"onelogin-client-secret", "onelogin client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"detectify-api-key", "detectify api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"wiz-client-secret", "wiz client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"jupiterone-api-token", "jupiterone api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ldap-url", "ldaps://binduser:SuperSecretPassword@ldap.example.com/ou=people", "ldaps://binduser:SuperSecretPassword@ldap.example.com/ou=people"},
		{"loginradius-api-secret", "loginradius api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"stytch-secret", "secret-live-" + strings.Repeat("A", 40), "secret-live-" + strings.Repeat("A", 40)},
		{"openvpn-static-key", "-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat("a", 600) + "\n-----END OpenVPN Static key V1-----", "-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat("a", 600) + "\n-----END OpenVPN Static key V1-----"},
		{"azure-entra-client-secret", "AZURE_CLIENT_SECRET=client_secret=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"twitter-bearer-token", "twitter bearer_token=\"AAAA" + strings.Repeat("A", 100) + "\"", "AAAA" + strings.Repeat("A", 100)},
		{"twitch-client-secret", "twitch client_secret=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"twitch-access-token", "twitch access_token=\"" + strings.Repeat("a", 30) + "\"", strings.Repeat("a", 30)},
		{"ipinfo-token", "ipinfo token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"coinlayer-api-key", "coinlayer api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"coinlib-api-key", "coinlib api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"cryptocompare-api-key", "cryptocompare api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"bitcoinaverage-api-key", "bitcoinaverage public_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"worldcoinindex-api-key", "worldcoinindex api_key=\"" + strings.Repeat("A", 35) + "\"", strings.Repeat("A", 35)},
		{"blocknative-api-key", "blocknative api_key=\"" + strings.Repeat("A", 36) + "\"", strings.Repeat("A", 36)},
		{"fixerio-api-key", "fixer.io access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"currencylayer-api-key", "currencylayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"exchangerate-api-key", "exchangerate-api api_key=\"" + strings.Repeat("A", 24) + "\"", strings.Repeat("A", 24)},
		{"exchangeratesapi-api-key", "exchangeratesapi access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"currencyfreaks-api-key", "currencyfreaks api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"currencyscoop-api-key", "currencyscoop api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"fastforex-api-key", "fastforex api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"marketstack-api-key", "marketstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"financialmodelingprep-api-key", "financialmodelingprep api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"finnhub-api-key", "finnhub api_key=\"" + strings.Repeat("A", 20) + "\"", strings.Repeat("A", 20)},
		{"tradier-token", "tradier access_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"twelvedata-api-key", "twelvedata api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"vatlayer-api-key", "vatlayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"worldweather-api-key", "worldweatheronline api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"positionstack-api-key", "positionstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"geocodio-api-key", "geocodio api_key=\"" + strings.Repeat("A", 39) + "\"", strings.Repeat("A", 39)},
		{"fastly-personal-token", "fastly personal_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"telnyx-api-key", "telnyx api_key=KEY" + strings.Repeat("A", 40), "KEY" + strings.Repeat("A", 40)},
		{"vagrant-cloud-token", "vagrantcloud token=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"zeplin-token", "zeplin token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"vultr-api-key", "vultr api_key=\"" + strings.Repeat("a", 36) + "\"", strings.Repeat("a", 36)},
		{"bitly-access-token", "bitly access_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"algolia-admin-key", "algolia admin_api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"typesense-api-key", "typesense.net x-typesense-api-key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"meilisearch-master-key", "meilisearch master_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"elastic-cloud-api-key", "cloud.elastic.co api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"elastic-app-search-key", "app-search private_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bonsai-elasticsearch-api-key", "bonsai.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"searchspring-api-key", "searchspring.net api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"constructorio-api-token", "constructor.io api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"coveo-api-key", "platform.cloud.coveo.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"yext-api-key", "api.yext.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"opensearch-api-key", "opensearch api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"airbrake-project-key", "airbrake project_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"airbrake-user-key", "airbrake user_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"bugsnag-api-key", "bugsnag api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"infura-project-id", "infura project_id=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"messagebird-api-key", "messagebird api_key=live_ABCDEFGHIJKLMNOPQRSTUVWXY", "live_ABCDEFGHIJKLMNOPQRSTUVWXY"},
		{"pinata-jwt", "pinata jwt=\"eyJ" + strings.Repeat("A", 24) + ".eyJ" + strings.Repeat("B", 24) + "." + strings.Repeat("C", 24) + "\"", "eyJ" + strings.Repeat("A", 24) + ".eyJ" + strings.Repeat("B", 24) + "." + strings.Repeat("C", 24)},
		{"pushbullet-token", "pushbullet access_token=o." + strings.Repeat("A", 32), "o." + strings.Repeat("A", 32)},
		{"sendbird-api-token", "sendbird api_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"stormglass-api-key", "stormglass api_key=\"" + strings.Repeat("A", 73) + "\"", strings.Repeat("A", 73)},
		{"todoist-api-token", "todoist token=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"uploadcare-secret-key", "uploadcare secret_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"bunny-api-key", "api.bunny.net access_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"imgix-api-token", "api.imgix.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"akamai-client-secret", ".edgerc akamai client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"keycdn-api-key", "api.keycdn.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"filestack-api-key", "cdn.filestackcontent.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bytescale-api-key", "api.bytescale.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"transloadit-auth-key", "api2.transloadit.com auth_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gumlet-api-key", "api.gumlet.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"imageengine-api-token", "control-api.imageengine.io api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tinypng-api-key", "api.tinify.com api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"browserstack-access-key", "browserstack access_key=\"" + strings.Repeat("A", 20) + "\"", strings.Repeat("A", 20)},
		{"cloudsmith-api-key", "cloudsmith api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"eventbrite-private-token", "eventbrite private_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"harvest-access-token", "harvest access_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"lokalise-token", "lokalise api_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"maxmind-license-key", "maxmind license_key=\"" + strings.Repeat("A", 16) + "\"", strings.Repeat("A", 16)},
		{"nylas-api-key", "nylas api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"pipedream-api-key", "pipedream api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"percy-token", "PERCY_TOKEN=token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"crowdin-token", "crowdin personal_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"postageapp-api-key", "postageapp api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"sendbird-organization-api-token", "sendbird organization_api_token=\"" + strings.Repeat("a", 24) + "\"", strings.Repeat("a", 24)},
		{"checkly-api-key", "checkly api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"incidentio-api-key", "api.incident.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"firehydrant-api-key", "api.firehydrant.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"squadcast-api-token", "api.squadcast.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ilert-api-key", "api.ilert.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"xmatters-api-token", "api.xmatters.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"semgrep-app-token", "semgrep.dev app_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"socketdev-api-key", "api.socket.dev api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aikido-api-token", "app.aikido.dev api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"infisical-service-token", "app.infisical.com service_token=\"st." + strings.Repeat("A", 48) + "\"", "st." + strings.Repeat("A", 48)},
		{"cronitor-api-key", "cronitor.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"confluent-api-secret", "confluent api_secret=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"docusign-client-secret", "docusign client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gocardless-access-token", "gocardless access_token=live_" + strings.Repeat("A", 48), "live_" + strings.Repeat("A", 48)},
		{"gumroad-access-token", "gumroad access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"hellosign-api-key", "hellosign api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"mailboxlayer-api-key", "mailboxlayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"mediastack-api-key", "mediastack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"opencage-api-key", "opencage api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"packagecloud-token", "packagecloud token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"phrase-access-token", "phrase access_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"semaphore-api-token", "semaphore api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"scrutinizer-token", "scrutinizer token=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"saucelabs-access-key", "saucelabs access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"lessannoyingcrm-api-key", "lessannoyingcrm api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"meaningcloud-api-key", "meaningcloud api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"openuv-api-key", "openuv api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"pandascore-api-key", "pandascore api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"paperform-api-key", "paperform api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"parsehub-api-key", "parsehub api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"pdfshift-api-key", "pdfshift api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"peopledatalabs-api-key", "peopledatalabs api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"plivo-auth-token", "plivo auth_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"rapidapi-key", "rapidapi x-rapidapi-key=\"" + strings.Repeat("A", 50) + "\"", strings.Repeat("A", 50)},
		{"scraperapi-key", "scraperapi api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"scrapestack-api-key", "scrapestack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"scrapingbee-api-key", "scrapingbee api_key=\"" + strings.Repeat("A", 80) + "\"", strings.Repeat("A", 80)},
		{"serpstack-api-key", "serpstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"shotstack-api-key", "shotstack api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"signalwire-api-token", "signalwire api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"testingbot-secret", "testingbot secret=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"abstract-api-key", "abstract api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"alchemy-api-key", "alchemy api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"apify-token", "apify token=apify_api_" + strings.Repeat("A", 40), "apify_api_" + strings.Repeat("A", 40)},
		{"apilayer-key", "apilayer access_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"bannerbear-api-key", "bannerbear api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"baremetrics-api-key", "baremetrics api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"beamer-api-key", "beamer api_key=\"" + strings.Repeat("A", 45) + "=\"", strings.Repeat("A", 45) + "="},
		{"bitbar-api-key", "bitbar api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"blazemeter-api-key", "blazemeter api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"buttercms-api-token", "buttercms api_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"canny-api-key", "canny api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"chartmogul-api-key", "chartmogul api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"clearbit-api-key", "clearbit api_key=\"" + strings.Repeat("a", 35) + "\"", strings.Repeat("a", 35)},
		{"clockify-api-key", "clockify api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cloudconvert-api-key", "cloudconvert api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cloudmersive-api-key", "cloudmersive api_key=12345678-1234-1234-1234-123456789abc", "12345678-1234-1234-1234-123456789abc"},
		{"convertapi-secret", "convertapi secret=\"secret_" + strings.Repeat("A", 16) + "\"", "secret_" + strings.Repeat("A", 16)},
		{"convertkit-api-secret", "convertkit api_secret=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"dailyco-api-key", "daily.co api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"deepai-api-key", "deepai api_key=\"" + strings.Repeat("a", 36) + "\"", strings.Repeat("a", 36)},
		{"delighted-api-key", "delighted api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"deputy-api-token", "deputy access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fullstory-api-key", "fullstory api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"flagsmith-server-key", "api.flagsmith.com server_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"growthbook-api-key", "api.growthbook.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"unleash-api-token", "app.unleash-hosted.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"splitio-api-key", "sdk.split.io sdk_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"statsig-server-secret", "api.statsig.com server_secret=\"secret-" + strings.Repeat("A", 48) + "\"", "secret-" + strings.Repeat("A", 48)},
		{"configcat-sdk-key", "cdn-global.configcat.com sdk_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"vwo-api-token", "dev.visualwebsiteoptimizer.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"abtasty-api-key", "api.abtasty.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"hotjar-api-token", "api.hotjar.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"logrocket-api-key", "api.logrocket.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"pendo-integration-key", "api.pendo.io integration_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"heap-api-key", "api.heap.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"contentsquare-api-key", "api.contentsquare.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gorgias-api-key", "api.gorgias.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"kustomer-api-token", "api.kustomerapp.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"crisp-api-token", "api.crisp.chat api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"userpilot-api-key", "api.userpilot.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"chameleon-api-key", "api.chameleon.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"productboard-api-token", "api.productboard.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"uservoice-api-token", "api.uservoice.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"productfruits-api-key", "api.productfruits.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"vitally-api-key", "api.vitally.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"planhat-api-token", "api.planhat.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"geoapify-api-key", "geoapify api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"graphhopper-api-key", "graphhopper api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"hunter-api-key", "hunter api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"imagekit-private-key", "imagekit private_key=private_" + strings.Repeat("A", 32), "private_" + strings.Repeat("A", 32)},
		{"kickbox-api-key", "kickbox api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"klipfolio-api-key", "klipfolio api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"lob-api-key", "lob api_key=live_" + strings.Repeat("A", 35), "live_" + strings.Repeat("A", 35)},
		{"moosend-api-key", "moosend api_key=12345678-1234-1234-1234-123456789abc", "12345678-1234-1234-1234-123456789abc"},
		{"neutrinoapi-api-key", "neutrinoapi api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"numverify-api-key", "numverify access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"omnisend-api-key", "omnisend api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"owlbot-api-key", "owlbot token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"pandadoc-api-key", "pandadoc api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"partnerstack-api-key", "partnerstack token=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"pastebin-api-key", "pastebin api_dev_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"paymongo-secret-key", "paymongo secret_key=sk_live_" + strings.Repeat("A", 40), "sk_live_" + strings.Repeat("A", 40)},
		{"photoroom-api-key", "photoroom api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"proxycrawl-api-token", "proxycrawl token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"qase-api-token", "qase api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"rebrandly-api-key", "rebrandly api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"repairshopr-api-key", "repairshopr api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"replyio-api-key", "reply.io api_key=\"" + strings.Repeat("A", 24) + "\"", strings.Repeat("A", 24)},
		{"restpack-htmltopdf-api-key", "restpack htmltopdf api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"restpack-screenshot-api-key", "restpack screenshot api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"rocketreach-api-key", "rocketreach api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"route4me-api-key", "route4me api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"salesflare-api-key", "salesflare api_key=\"" + strings.Repeat("A", 45) + "\"", strings.Repeat("A", 45)},
		{"attio-api-key", "api.attio.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"affinity-api-key", "api.affinity.co api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"height-api-key", "api.height.app api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gong-api-token", "api.gong.io access_key_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"chorus-api-key", "api.chorus.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"outreach-api-token", "api.outreach.io access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"salesloft-api-key", "api.salesloft.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clay-api-key", "api.clay.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"instantly-api-key", "api.instantly.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"smartlead-api-key", "api.smartlead.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"salesforce-pardot-client-secret", "pi.pardot.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"greenhouse-harvest-api-key", "harvest.greenhouse.io harvest_api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"lever-api-key", "api.lever.co api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ashby-api-key", "api.ashbyhq.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"workable-api-token", "api.workable.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"smartrecruiters-api-key", "api.smartrecruiters.com x-smarttoken=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"personio-api-secret", "api.personio.de client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"hibob-service-token", "api.hibob.com service_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bamboohr-api-key", "api.bamboohr.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"rippling-api-token", "api.rippling.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"deel-api-token", "api.deel.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gusto-api-token", "api.gusto.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"workday-client-secret", "workday.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"adzuna-api-key", "adzuna app_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"airvisual-api-key", "airvisual api_key=\"" + strings.Repeat("A", 36) + "\"", strings.Repeat("A", 36)},
		{"amadeus-api-secret", "amadeus client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ambee-api-key", "ambee api_key=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"amplitude-api-key", "amplitude api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"apiflash-access-key", "apiflash access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"apitemplate-api-key", "apitemplate api_key=\"" + strings.Repeat("A", 39) + "\"", strings.Repeat("A", 39)},
		{"appcues-api-key", "appcues api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"appfollow-api-key", "appfollow token=\"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." + strings.Repeat("A", 74) + "." + strings.Repeat("A", 43) + "\"", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." + strings.Repeat("A", 74) + "." + strings.Repeat("A", 43)},
		{"autoklose-api-key", "autoklose api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"aviationstack-api-key", "aviationstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"ayrshare-api-key", "ayrshare api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"besttime-api-key", "besttime api_key=\"pri_" + strings.Repeat("a", 32) + "\"", "pri_" + strings.Repeat("a", 32)},
		{"brandfetch-api-key", "brandfetch token=\"" + strings.Repeat("A", 43) + "=\"", strings.Repeat("A", 43) + "="},
		{"browshot-api-key", "browshot api_key=\"" + strings.Repeat("A", 13) + "-" + strings.Repeat("A", 14) + "\"", strings.Repeat("A", 13) + "-" + strings.Repeat("A", 14)},
		{"calendarific-api-key", "calendarific api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"carboninterface-api-key", "carbon interface token=\"" + strings.Repeat("A", 21) + "\"", strings.Repeat("A", 21)},
		{"craftmypdf-api-key", "craftmypdf api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"currentsapi-api-key", "currentsapi api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"debounce-api-key", "debounce api_key=\"" + strings.Repeat("A", 13) + "\"", strings.Repeat("A", 13)},
		{"detectlanguage-api-key", "detectlanguage api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"clarifai-api-key", "clarifai pat=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clicksend-api-key", "clicksend api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"codemagic-api-token", "codemagic api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"databox-api-token", "databox token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"diffbot-api-token", "diffbot token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"edamam-api-key", "edamam app_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ethplorer-api-key", "ethplorer api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"faceplusplus-api-key", "faceplusplus api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"geckoboard-api-key", "geckoboard api_key=\"" + strings.Repeat("A", 44) + "\"", strings.Repeat("A", 44)},
		{"hasura-admin-secret", "hasura admin_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"holidayapi-key", "holidayapi key=\"" + strings.Repeat("A", 36) + "\"", strings.Repeat("A", 36)},
		{"html2pdf-api-key", "html2pdf api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"ip2location-api-key", "ip2location api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ipapi-api-key", "ipapi access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"ipinfodb-api-key", "ipinfodb api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"jotform-api-key", "jotform api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"keenio-api-key", "keen.io master_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"languagelayer-api-key", "languagelayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"linenotify-token", "line notify token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"linkpreview-api-key", "linkpreview api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"vercel-token", "VERCEL_TOKEN=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"railway-token", "railway_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"render-api-key", "api.render.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"koyeb-api-token", "api.koyeb.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"northflank-api-token", "api.northflank.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"qovery-api-token", "api.qovery.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"porter-api-token", "dashboard.porter.run api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"envkey-api-key", "envkey.com server_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"akeyless-access-secret", "api.akeyless.io access_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"platformsh-api-token", "api.platform.sh api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"flightcontrol-api-key", "app.flightcontrol.dev api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cleavr-api-key", "cleavr.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"travisci-token", "TRAVIS_TOKEN=\"" + strings.Repeat("A", 22) + "\"", strings.Repeat("A", 22)},
		{"betterstack-api-key", "betterstack_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"customerio-api-key", "customer.io key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"trello-api-key", "trello_api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"helpscout-api-key", "helpscout key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"mailerlite-api-key", "mailerlite_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"mandrill-api-key", "mandrill_key=\"" + strings.Repeat("A", 22) + "\"", strings.Repeat("A", 22)},
		{"onesignal-api-key", "onesignal_rest_api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"copper-api-key", "copper_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"capsulecrm-api-key", "capsulecrm_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"apollo-api-key", "apollo_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"lemlist-api-key", "lemlist_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"getresponse-api-key", "getresponse_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"alienvault-otx-api-key", "alienvault_otx_key=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"censys-api-key", "censys_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"vpnapi-key", "vpnapi.io key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ipqualityscore-api-key", "ipqualityscore key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ipstack-api-key", "ipstack key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"ipgeolocation-api-key", "ipgeolocation key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"zerotier-api-token", "zerotier token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"logzio-token", "logz.io token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"codeclimate-token", "codeclimate repo token=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"codacy-api-token", "codacy token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"coveralls-repo-token", "coveralls token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"weatherstack-api-key", "weatherstack key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"accuweather-api-key", "accuweather key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"weatherbit-api-key", "weatherbit key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"mapquest-api-key", "mapquest key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"aiven-token", "aiven_token=\"" + strings.Repeat("A", 372) + "\"", strings.Repeat("A", 372)},
		{"abuseipdb-api-key", "abuseipdb_key=\"" + strings.Repeat("a", 80) + "\"", strings.Repeat("a", 80)},
		{"sonarcloud-token", "SONAR_TOKEN=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"jumpcloud-api-key", "jumpcloud_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"pipedrive-api-token", "pipedrive_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"sparkpost-api-key", "sparkpost_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"dropbox-token", "sl.u." + strings.Repeat("A", 140), "sl.u." + strings.Repeat("A", 140)},
		{"readme-api-key", "rdme_" + strings.Repeat("a", 70), "rdme_" + strings.Repeat("a", 70)},
		{"rootly-api-key", "rootly_" + strings.Repeat("a", 64), "rootly_" + strings.Repeat("a", 64)},
		{"web3storage-token", "web3 " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ" + strings.Repeat("A", 120) + "." + strings.Repeat("B", 40), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ" + strings.Repeat("A", 120) + "." + strings.Repeat("B", 40)},
		{"stripe-payment-intent-client-secret", "pi_" + strings.Repeat("A", 24) + "_secret_" + strings.Repeat("B", 25), "pi_" + strings.Repeat("A", 24) + "_secret_" + strings.Repeat("B", 25)},
		{"checkout-secret-key", "checkout sk_test_12345678-1234-1234-1234-123456789abc", "sk_test_12345678-1234-1234-1234-123456789abc"},
		{"loggly-token", "loggly customer_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"mixpanel-api-secret", "mixpanel api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mockaroo-api-key", "mockaroo api_key=\"abcdefgh\"", "abcdefgh"},
		{"mux-token-secret", "mux token_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nutritionix-api-key", "nutritionix app_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"oanda-api-token", "oanda api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"onfleet-api-key", "onfleet api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"pdflayer-api-key", "pdflayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"pepipost-api-key", "pepipost api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"pivotaltracker-api-token", "pivotal tracker api_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"pixabay-api-key", "pixabay api_key=\"" + strings.Repeat("a", 16) + "-" + strings.Repeat("a", 17) + "\"", strings.Repeat("a", 16) + "-" + strings.Repeat("a", 17)},
		{"podio-api-token", "podio access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"pubnub-publish-key", "pubnub publish_key=pub-c-" + strings.Repeat("A", 36), "pub-c-" + strings.Repeat("A", 36)},
		{"pubnub-subscribe-key", "pubnub subscribe_key=sub-c-" + strings.Repeat("A", 36), "sub-c-" + strings.Repeat("A", 36)},
		{"pusher-channel-key", "pusher channel_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"qualaroo-api-key", "qualaroo api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"rawg-api-key", "rawg api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ringcentral-client-secret", "ringcentral client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"scrapeowl-api-key", "scrapeowl api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"scrapfly-api-key", "scrapfly api_key=\"scp-live-" + strings.Repeat("a", 32) + "\"", "scp-live-" + strings.Repeat("a", 32)},
		{"screenshotapi-key", "screenshotapi api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"screenshotlayer-api-key", "screenshotlayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"selectpdf-api-key", "selectpdf api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"sheety-api-key", "sheety bearer_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"shipday-api-key", "shipday api_key=\"AAAAA.AAAAA" + strings.Repeat("A", 20) + "\"", "AAAAA.AAAAA" + strings.Repeat("A", 20)},
		{"signable-api-key", "signable api_key=\"" + strings.Repeat("A", 15) + "-" + strings.Repeat("A", 16) + "\"", strings.Repeat("A", 15) + "-" + strings.Repeat("A", 16)},
		{"signnow-api-token", "api.signnow.com access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"adobe-sign-client-secret", "api.adobesign.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"signaturit-api-key", "signaturit token=\"" + strings.Repeat("A", 86) + "\"", strings.Repeat("A", 86)},
		{"simplesat-api-key", "simplesat api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"smartystreets-auth-token", "smarty streets auth_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"snipcart-api-key", "snipcart secret_api_key=\"" + strings.Repeat("A", 75) + "\"", strings.Repeat("A", 75)},
		{"spoonacular-api-key", "spoonacular api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"sportsmonk-api-token", "sportsmonk api_token=\"" + strings.Repeat("A", 60) + "\"", strings.Repeat("A", 60)},
		{"spotify-client-secret", "spotify client_secret=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"statuscake-api-key", "statuscake api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"stockdata-api-key", "stockdata token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"storychief-api-key", "storychief api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"shippo-api-token", "api.goshippo.com api_token=\"shippo_live_" + strings.Repeat("A", 48) + "\"", "shippo_live_" + strings.Repeat("A", 48)},
		{"easypost-api-key", "api.easypost.com api_key=\"EZAK" + strings.Repeat("A", 48) + "\"", "EZAK" + strings.Repeat("A", 48)},
		{"shipstation-api-secret", "ssapi.shipstation.com api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"shipengine-api-key", "api.shipengine.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aftership-api-key", "api.aftership.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"easyship-api-token", "api.easyship.com api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sendcloud-api-key", "panel.sendcloud.sc api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"strava-client-secret", "strava client_secret=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"swiftype-api-key", "swiftype api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tatum-api-key", "tatum api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"taxjar-api-token", "taxjar api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"avalara-license-key", "rest.avatax.com license_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"vertex-tax-api-secret", "vertexinc.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"taxbit-api-key", "api.taxbit.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"textmagic-api-key", "textmagic api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tiingo-api-token", "tiingo api_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"timecamp-api-token", "timecamp token=\"" + strings.Repeat("a", 26) + "\"", strings.Repeat("a", 26)},
		{"timezoneapi-key", "timezoneapi api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"toggltrack-api-token", "toggltrack api_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"tomtom-api-key", "tomtom key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"transferwise-api-token", "transferwise api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"unsplash-access-key", "unsplash access_key=\"" + strings.Repeat("A", 43) + "\"", strings.Repeat("A", 43)},
		{"userstack-api-key", "userstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"visualcrossing-api-key", "visual crossing api_key=\"" + strings.Repeat("A", 25) + "\"", strings.Repeat("A", 25)},
		{"voicegain-api-key", "voicegain api_key=\"ey" + strings.Repeat("A", 34) + ".ey" + strings.Repeat("A", 108) + "." + strings.Repeat("A", 43) + "\"", "ey" + strings.Repeat("A", 34) + ".ey" + strings.Repeat("A", 108) + "." + strings.Repeat("A", 43)},
		{"wepay-client-secret", "wepay client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"yandex-api-key", "yandex api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"yelp-api-key", "yelp bearer_token=\"" + strings.Repeat("A", 128) + "\"", strings.Repeat("A", 128)},
		{"ynab-api-token", "ynab personal_access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zenrows-api-key", "zenrows api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"zenscrape-api-key", "zenscrape api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"zenserp-api-key", "zenserp api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"zerobounce-api-key", "zerobounce api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"zipcodebase-api-key", "zipcodebase api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"bitfinex-api-secret", "bitfinex api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bitmex-api-secret", "bitmex secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"kucoin-api-secret", "kucoin api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"smartsheet-access-token", "smartsheet access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tableau-pat-secret", "tableau pat_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"thousandeyes-token", "thousandeyes bearer_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ticketmaster-api-key", "ticketmaster consumer_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"theoddsapi-key", "the odds api api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"thinkific-api-key", "thinkific api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"canvas-instructure-access-token", "canvas.instructure.com access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"blackboard-rest-secret", "learn.blackboard.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"moodle-webservice-token", "moodle wstoken=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"brightspace-client-secret", "auth.brightspace.com client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"schoology-api-secret", "api.schoology.com consumer_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"teachable-api-key", "developers.teachable.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"kajabi-api-key", "api.kajabi.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"learnworlds-api-key", "api.learnworlds.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"talentlms-api-key", "example.talentlms.com api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"docebo-api-token", "api.docebo.com access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ubidots-token", "ubidots token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"uclassify-api-key", "uclassify api_key=\"" + strings.Repeat("A", 12) + "\"", strings.Repeat("A", 12)},
		{"upcdatabase-api-key", "upc database api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"uplead-api-key", "uplead api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"vbout-api-key", "vbout api_key=\"" + strings.Repeat("1", 25) + "\"", strings.Repeat("1", 25)},
		{"veriphone-api-key", "veriphone api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"walkscore-api-key", "walk score api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"websitepulse-api-key", "websitepulse api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"whoxy-api-key", "whoxy api_key=\"" + strings.Repeat("A", 33) + "\"", strings.Repeat("A", 33)},
		{"wistia-api-token", "wistia api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"wit-ai-token", "wit.ai server_access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ticket-tailor-api-key", "ticket tailor api_key=\"sk_1234_123456_" + strings.Repeat("a", 32) + "\"", "sk_1234_123456_" + strings.Repeat("a", 32)},
		{"tmetric-api-token", "tmetric api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"teamgate-api-key", "teamgate api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"teamworkspaces-token", "teamwork spaces token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"signupgenius-api-key", "signup genius api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"speechtextai-api-key", "speechtext.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sirv-api-token", "sirv api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"siteleaf-api-key", "siteleaf api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"skrapp-api-key", "skrapp api_key=\"" + strings.Repeat("A", 42) + "\"", strings.Repeat("A", 42)},
		{"skybiometry-api-key", "skybiometry api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"simplynoted-api-key", "simply noted api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"simvoly-api-key", "simvoly api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sinch-message-api-token", "sinch message_api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sslmate-api-key", "sslmate api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"statuspal-api-key", "statuspal api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"storecove-api-key", "storecove token=\"" + strings.Repeat("A", 43) + "\"", strings.Repeat("A", 43)},
		{"stormboard-api-key", "stormboard api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"streak-api-key", "streak api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"stripo-api-key", "stripo api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sugester-api-token", "sugester api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"abyssale-api-key", "abyssale api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"adafruit-io-key", "adafruit io aio_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"adobe-io-client-secret", "adobe io client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aeroworkflow-api-key", "aero workflow api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"agora-app-certificate", "agora app_certificate=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"airship-api-key", "airship master_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"alconost-api-key", "alconost api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"alegra-api-token", "alegra api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aletheia-api-key", "aletheia api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"allsports-api-key", "all sports api_key=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"anypoint-client-secret", "anypoint client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"apacta-api-key", "apacta api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"api2cart-api-key", "api2cart api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"apideck-api-key", "apideck api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"apifonica-api-key", "apifonica api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"apimatic-api-key", "apimatic api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"apimetrics-api-key", "apimetrics api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"appointedd-api-key", "appointedd api_key=\"" + strings.Repeat("A", 88) + "\"", strings.Repeat("A", 88)},
		{"appoptics-api-token", "appoptics api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"appsynergy-api-key", "app synergy api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"apptivo-api-key", "apptivo access_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"artsy-api-token", "artsy api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"atera-api-key", "atera api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"atlassian-datacenter-token", "atlassian data center personal_access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"audd-api-token", "audd api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"autodesk-client-secret", "autodesk client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"autopilot-api-key", "autopilot api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"axonaut-api-key", "axonaut api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"aylien-api-key", "aylien application_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"beebole-api-token", "beebole api_token=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"besnappy-api-key", "be snappy api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"billomat-api-key", "billomat api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"blitapp-api-key", "blitapp api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"blogger-api-key", "blogger api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bombbomb-api-key", "bomb bomb api_key=\"eyJ" + strings.Repeat("A", 20) + ".eyJ" + strings.Repeat("A", 20) + "." + strings.Repeat("A", 20) + "\"", "eyJ" + strings.Repeat("A", 20) + ".eyJ" + strings.Repeat("A", 20) + "." + strings.Repeat("A", 20)},
		{"boostnote-api-token", "boost note api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"borgbase-api-key", "borgbase api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"buddyns-api-key", "buddy ns api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"budibase-api-key", "budibase api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bugherd-api-key", "bugherd api_key=\"" + strings.Repeat("a", 22) + "\"", strings.Repeat("a", 22)},
		{"bulbul-api-key", "bulbul api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"bulksms-api-token", "bulk sms api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"caflou-api-key", "caflou api_key=\"eyJhbGciOiJIUzI1NiJ9." + strings.Repeat("A", 80) + "." + strings.Repeat("A", 43) + "\"", "eyJhbGciOiJIUzI1NiJ9." + strings.Repeat("A", 80) + "." + strings.Repeat("A", 43)},
		{"calorieninja-api-key", "calorie ninjas api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"campayn-api-key", "campayn api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"captaindata-api-key", "captain data api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cashboard-api-key", "cashboard api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"caspio-api-key", "caspio client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"centralstationcrm-api-token", "central station crm api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cexio-api-key", "cex.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"chatbot-api-key", "chatbot api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"chatfuel-api-key", "chatfuel api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"chec-api-key", "chec.io secret_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"checkvist-api-token", "checkvist api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cicero-api-key", "cicero api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clickhelp-api-key", "clickhelp api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cliengo-api-key", "cliengo api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"clientary-api-key", "clientary api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clinchpad-api-key", "clinchpad api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clockworksms-api-key", "clockwork sms api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"avaza-api-token", "avaza api_token=\"123-" + strings.Repeat("a", 40) + "\"", "123-" + strings.Repeat("a", 40)},
		{"cloudelements-api-key", "cloud elements user_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cloudimage-api-key", "cloudimage api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cloudplan-api-key", "cloudplan api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"cloverly-api-key", "cloverly api_key=\"" + strings.Repeat("a", 13) + ":" + strings.Repeat("a", 14) + "\"", strings.Repeat("a", 13) + ":" + strings.Repeat("a", 14)},
		{"cloze-api-key", "cloze api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"clustdoc-api-key", "clustdoc api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"codequiry-api-key", "codequiry api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"collect2-api-key", "collect2 api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"column-api-key", "column secret=\"live_" + strings.Repeat("A", 27) + "\"", "live_" + strings.Repeat("A", 27)},
		{"commercejs-api-key", "commerce.js secret_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"commodities-api-key", "commodities access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"companyhub-api-key", "company hub api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"conversiontools-api-key", "conversion tools api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"convier-api-key", "convier api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"countrylayer-api-key", "countrylayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"currencycloud-api-key", "currency cloud api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"customerguru-api-key", "customer.guru api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"d7network-api-token", "d7 network api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dandelion-api-key", "dandelion token=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"dareboost-api-key", "dareboost api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"datagov-api-key", "data.gov api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"demio-api-key", "demio secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dfuse-api-key", "dfuse token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"diggernaut-api-key", "diggernaut api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"disqus-api-key", "disqus api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ditto-api-key", "ditto api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dnscheck-api-key", "dns check api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"docparser-api-key", "docparser api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"documo-api-key", "documo api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dotdigital-api-key", "dot digital password=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dovico-api-key", "dovico api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dronahq-api-key", "drona hq api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"droneci-token", "drone ci token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"duply-api-key", "duply api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dynalist-api-token", "dynalist api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dyspatch-api-key", "dyspatch api_key=\"" + strings.Repeat("A", 52) + "\"", strings.Repeat("A", 52)},
		{"eagleeyenetworks-api-key", "eagle eye networks secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"easyinsight-api-key", "easy insight api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ecostruxureit-api-key", "ecostruxure it api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"eightxeight-api-key", "8x8 api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"dwolla-api-key", "dwolla client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"enablex-api-key", "enablex secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"enigma-api-key", "enigma api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"envoy-api-key", "envoy api_key=\"" + strings.Repeat("A", 220) + "\"", strings.Repeat("A", 220)},
		{"eraser-api-key", "eraser api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"everhour-api-key", "everhour api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"exportsdk-api-key", "export sdk api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"extractorapi-key", "extractor api api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"feedier-api-key", "feedier api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"fetchrss-api-key", "fetch rss api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fibery-api-token", "fibery api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fileio-api-key", "file.io api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"finage-api-key", "finage api_key=\"API_KEY" + strings.Repeat("A", 32) + "\"", "API_KEY" + strings.Repeat("A", 32)},
		{"findl-api-key", "findl api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"flatio-api-key", "flatio api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fleetbase-api-key", "fleetbase secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"flexport-api-key", "flexport api_key=\"shltm_" + strings.Repeat("A", 40) + "\"", "shltm_" + strings.Repeat("A", 40)},
		{"flickr-api-key", "flickr api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"flightapi-key", "flight api api_key=\"" + strings.Repeat("a", 24) + "\"", strings.Repeat("a", 24)},
		{"flightlabs-api-key", "flight labs access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"flightstats-api-key", "flight stats app_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"float-api-key", "float api_key=\"" + strings.Repeat("a", 16) + strings.Repeat("A", 42) + "=\"", strings.Repeat("a", 16) + strings.Repeat("A", 42) + "="},
		{"flowflu-api-key", "flowlu api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fmfw-api-key", "fmfw secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"formbucket-api-key", "form bucket api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"formcraft-api-key", "form craft api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"formio-api-key", "form.io jwt_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"formsite-api-key", "formsite api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"foursquare-api-key", "foursquare client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"frameio-api-token", "frame.io api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"freshbooks-api-key", "fresh books token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fulcrum-api-token", "fulcrum api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"fxmarket-api-key", "fx market api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gengo-api-key", "gengo private_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"geocodify-api-key", "geocodify api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"geoipifi-api-key", "geo.ipify api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"getemail-api-key", "get email api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"getemails-api-key", "get emails api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"getgeoapi-key", "get geo api api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"getgist-api-key", "get gist api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"getsandbox-api-key", "get sandbox api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gitter-token", "gitter access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"glassnode-api-key", "glassnode api_key=\"" + strings.Repeat("A", 27) + "\"", strings.Repeat("A", 27)},
		{"gocanvas-api-key", "go canvas api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"godaddy-api-key", "go daddy secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"goodday-api-key", "good day api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"graphcms-api-token", "graph cms auth_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"groovehq-api-key", "groove hq api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"gtmetrix-api-key", "gtmetrix api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"guru-api-key", "guru api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"gyazo-api-token", "gyazo access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"happyscribe-api-key", "happy scribe api_key=\"" + strings.Repeat("A", 24) + "\"", strings.Repeat("A", 24)},
		{"hive-api-key", "hive api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"hiveage-api-key", "hiveage api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"holistic-api-key", "holistic api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"humanity-api-key", "humanity api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"hybiscus-api-key", "hybiscus api_key=\"" + strings.Repeat("A", 43) + "\"", strings.Repeat("A", 43)},
		{"hypertrack-api-key", "hypertrack secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ibmcloud-user-key", "ibm cloud user_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"iconfinder-api-key", "iconfinder api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"iexapis-api-key", "iex apis api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"iexcloud-api-key", "iex cloud secret_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"imagga-api-key", "imagga api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"impala-api-key", "impala secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"insightly-api-key", "insightly api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"instabot-api-key", "instabot api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"instamojo-api-key", "instamojo auth_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"interseller-api-key", "interseller api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"intra42-api-key", "intra42 api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"intrinio-api-key", "intrinio api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"invoiceocean-api-key", "invoice ocean api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"juro-api-key", "juro token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"kanban-api-key", "kanban api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"kanbantool-api-key", "kanban tool api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"karmacrm-api-key", "karma crm api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"knapsackpro-api-token", "knapsack pro api_token=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"kontent-api-key", "kontent management_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"kylas-api-key", "kylas api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"leadfeeder-api-key", "leadfeeder api_key=\"" + strings.Repeat("A", 43) + "\"", strings.Repeat("A", 43)},
		{"lendflow-api-key", "lendflow secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"lexigram-api-key", "lexigram api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"kraken-api-secret", "kraken api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"larksuite-token", "larksuite tenant_access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"liveagent-api-key", "live agent api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"livestorm-api-key", "livestorm api_key=\"eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi" + strings.Repeat("A", 134) + "." + strings.Repeat("A", 43) + "\"", "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi" + strings.Repeat("A", 134) + "." + strings.Repeat("A", 43)},
		{"loadmill-api-key", "loadmill api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"loyverse-api-token", "loyverse api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"lunchmoney-api-token", "lunch money api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"luno-api-secret", "luno api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"m3o-api-key", "m3o api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"madkudu-api-key", "madkudu api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"magicbell-api-key", "magic bell secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"magnetic-api-key", "magnetic api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mailjetsms-api-token", "mailjet sms api_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"mailsac-api-key", "mailsac api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"manifest-api-key", "manifest api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mavenlink-api-token", "mavenlink api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"meistertask-api-token", "meister task api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"meraki-api-key", "meraki api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mesibo-api-token", "mesibo api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"metaapi-token", "meta api token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"metabase-api-key", "metabase session=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"metrilo-api-key", "metrilo api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mindmeister-api-token", "mind meister api_token=\"" + strings.Repeat("A", 43) + "\"", strings.Repeat("A", 43)},
		{"miro-api-token", "miro access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mite-api-key", "mite api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"mixmax-api-key", "mixmax api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"moderation-api-key", "moderation api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"moonclerk-api-key", "moon clerk secret=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"moralis-api-key", "moralis api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"mrticktock-api-key", "mr tick tock api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"myfreshworks-api-key", "myfreshworks api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"myintervals-api-key", "my intervals api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nasdaqdatalink-api-key", "nasdaq data link api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nethunt-api-key", "net hunt api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"netsuite-token-secret", "net suite token_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"newscatcher-api-key", "news catcher api_key=\"" + strings.Repeat("A", 43) + "\"", strings.Repeat("A", 43)},
		{"nexmo-api-key", "nexmo api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nftport-api-key", "nft port api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ngc-api-key", "nvidia ngc api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nicereply-api-key", "nice reply api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nimble-api-key", "nimble api_key=\"" + strings.Repeat("A", 30) + "\"", strings.Repeat("A", 30)},
		{"noticeable-api-key", "noticeable api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"nozbeteams-api-token", "nozbe teams api_token=\"" + strings.Repeat("A", 16) + "_" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 16) + "_" + strings.Repeat("A", 64)},
		{"nvapi-key", "nvapi api_key=\"nvapi-" + strings.Repeat("A", 64) + "\"", "nvapi-" + strings.Repeat("A", 64)},
		{"onedesk-api-key", "one desk api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"onepagecrm-api-key", "one page crm api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"oopspam-api-key", "oopspam api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"optimizely-api-key", "optimizely personal_access_token=\"" + strings.Repeat("A", 54) + "\"", strings.Repeat("A", 54)},
		{"overloop-api-key", "overloop api_key=\"" + strings.Repeat("A", 50) + "\"", strings.Repeat("A", 50)},
		{"paralleldots-api-key", "parallel dots api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"parsers-api-key", "parsers api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"parseur-api-key", "parseur api_key=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"paydirt-api-key", "paydirt api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"paymo-api-key", "paymo api_key=\"" + strings.Repeat("A", 44) + "\"", strings.Repeat("A", 44)},
		{"planview-leankit-api-key", "planview leankit api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"planyo-api-key", "planyo api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"pollsapi-key", "polls api api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"poloniex-api-secret", "poloniex api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"postbacks-api-key", "postbacks api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"powrbot-api-key", "powrbot api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"privacy-api-key", "privacy.com api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"prodpad-api-key", "prodpad api_key=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"prospectcrm-api-key", "prospect crm api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"protocolsio-api-token", "protocols.io api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"purestake-api-key", "purestake api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"qubole-api-token", "qubole api_token=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"ramp-api-key", "ramp secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"raven-api-key", "raven api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"reachmail-api-key", "reach mail api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"reallysimplesystems-api-key", "really simple systems api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"refiner-api-key", "refiner api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"rentman-api-token", "rentman api_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"requestfinance-api-key", "request finance secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"rev-ai-api-key", "rev.ai api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"revampcrm-api-key", "revamp crm api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"ritekit-api-key", "ritekit api_key=\"" + strings.Repeat("a", 44) + "\"", strings.Repeat("a", 44)},
		{"roaring-api-key", "roaring api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"robinhoodcrypto-api-secret", "robinhood crypto api_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"rownd-api-key", "rownd secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"runrunit-api-key", "runrun.it api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"salescookie-api-key", "sales cookie api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"salesmate-api-key", "salesmate api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"satismeter-project-key", "satis meter project_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"satismeter-write-key", "satis meter write_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"scalr-api-key", "scalr secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"scraperbox-api-key", "scraper box api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"scrapingant-api-key", "scraping ant api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"serphouse-api-key", "serp house api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sherpadesk-api-key", "sherpa desk api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"shutterstock-api-token", "shutterstock access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"shutterstock-oauth-client-secret", "shutterstock oauth client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"sigopt-api-token", "sigopt client_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"simfin-api-key", "simfin api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"square-app-secret", "square app_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"squarespace-api-key", "squarespace api_key=\"12345678-1234-1234-1234-123456789abc\"", "12345678-1234-1234-1234-123456789abc"},
		{"stitchdata-api-token", "stitch data api_token=\"" + strings.Repeat("a", 35) + "\"", strings.Repeat("a", 35)},
		{"supernotes-api-key", "supernotes api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"surveyanyplace-api-key", "survey anyplace api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"surveybot-api-key", "survey bot api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"surveysparrow-api-key", "survey sparrow api_key=\"" + strings.Repeat("A", 88) + "\"", strings.Repeat("A", 88)},
		{"survicate-api-key", "survicate api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"swell-api-key", "swell secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tallyfy-api-key", "tallyfy api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"technicalanalysisapi-key", "technical analysis api api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tefter-api-key", "tefter api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"teletype-api-key", "teletype api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"tly-api-key", "t.ly api_key=\"" + strings.Repeat("A", 60) + "\"", strings.Repeat("A", 60)},
		{"tokeet-api-key", "tokeet api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"travelpayouts-api-key", "travel payouts api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"tru-api-key", "tru.id client_secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"twist-api-token", "twist access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"tyntec-api-key", "tyntec secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"typetalk-api-token", "typetalk access_token=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"unifyid-api-key", "unify id secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"unplugg-api-key", "unplugg api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"upwave-api-key", "upwave api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"userflow-api-key", "userflow secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"verimail-api-key", "verimail api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"versioneye-api-key", "version eye api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"viewneo-api-key", "viewneo api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"voodoosms-api-key", "voodoo sms secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"vouchery-api-key", "vouchery api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"vyte-api-key", "vyte api_key=\"" + strings.Repeat("a", 50) + "\"", strings.Repeat("a", 50)},
		{"webscraper-api-key", "web scraper api_key=\"" + strings.Repeat("A", 60) + "\"", strings.Repeat("A", 60)},
		{"webscraping-api-key", "web scraping api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"worksnaps-api-key", "worksnaps api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"workstack-api-key", "workstack api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"yousign-api-key", "yousign secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zenkit-api-key", "zenkit api_key=\"abcdefgh-" + strings.Repeat("A", 32) + "\"", "abcdefgh-" + strings.Repeat("A", 32)},
		{"zipapi-key", "zip api api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zipbooks-api-key", "zip books api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zipcodeapi-key", "zip code api api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zonkafeedback-api-key", "zonka feedback api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"zulipchat-api-key", "zulip chat secret=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"aha-api-key", "example.aha.io token=" + strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"larksuite-app-secret", "larksuite app_id=cli_ABCDEFGHIJKLMNOP app_secret=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if !registryFinds(tc.id, tc.input, tc.secret) {
				t.Fatalf("expected %s to find %q in %q", tc.id, tc.secret, tc.input)
			}
		})
	}
}

func registryFinds(id, input, secret string) bool {
	for _, d := range DefaultRegistry() {
		for _, c := range d.Detect([]byte(input)) {
			if c.DetectorID == id && c.Secret == secret {
				return true
			}
		}
	}
	return false
}

func TestRedact(t *testing.T) {
	got := Redact("abcdefghijklmnop")
	if got != "abcd********mnop" {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestPlausibleSecretRejectsRegexFragments(t *testing.T) {
	if plausibleSecret(`[^\s*\"]+`) {
		t.Fatal("expected regex fragment to be rejected")
	}
}

func TestPlausibleSecretRejectsVariableReferences(t *testing.T) {
	cases := []string{
		`${sendgrid_api_key}`,
		`$SENDGRID_API_KEY`,
		`{{ sendgrid_api_key }}`,
		`$(SENDGRID_API_KEY)`,
		`$[variables.SENDGRID_API_KEY]`,
		`%SENDGRID_API_KEY%`,
		`!SENDGRID_API_KEY!`,
		`process.env.SENDGRID_API_KEY`,
		`os.Getenv("SENDGRID_API_KEY")`,
		`os.environ["SENDGRID_API_KEY"]`,
		`ENV.fetch("SENDGRID_API_KEY")`,
		`config.get("SENDGRID_API_KEY")`,
		`vault.read("secret/sendgrid")`,
		`ref+vault://secret/sendgrid`,
		`ENC[AES256_GCM,data:placeholder]`,
		`secrets.SENDGRID_API_KEY`,
		`sendgrid_api_key`,
		`PROD_DB_PASSWORD`,
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if plausibleSecret(tc) {
				t.Fatalf("expected variable reference to be rejected: %q", tc)
			}
		})
	}
	if !plausibleSecret(`production.AbCdEfGhIjKlMnOpQrStUvWx`) {
		t.Fatal("expected quoted-looking dotted literal to remain plausible")
	}
}

func TestAssignedSecretRejectsVariableReferences(t *testing.T) {
	cases := []string{
		`password=${sendgrid_api_key}`,
		`password=$SENDGRID_API_KEY`,
		`password=sendgrid_api_key_value`,
		`password=PROD_DB_PASSWORD`,
		`Server=tcp:db.example.com;User ID=app;Password=${ConnectionStrings.DSN_Remits.Password};`,
		`Server=tcp:db.example.com;User ID=app;Password=${ConnectionStrings.DSN_CueballRead.Password};`,
		`Server=tcp:db.example.com;User ID=app;Password="${ConnectionStrings.DSN_General.Password}";`,
		`Data Source=${ConnectionStrings.DSN_Remits.Server};Initial Catalog=Remits;Persist Security Info=True;User ID=Remitsuser;Password=${ConnectionStrings.DSN_Remits.Password}"/>`,
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if plausibleSecret(tc) {
				t.Fatalf("expected assigned variable reference to be ignored: %q", tc)
			}
		})
	}

	literal := "password=" + strings.Repeat("a", 24)
	if !registryFinds("generic-assigned-secret", literal, strings.Repeat("a", 24)) {
		t.Fatalf("expected literal assigned secret to be detected: %q", literal)
	}
	dottedLiteral := `production.AbCdEfGhIjKlMnOpQrStUvWx`
	if !registryFinds("generic-assigned-secret", `password="`+dottedLiteral+`"`, dottedLiteral) {
		t.Fatalf("expected quoted dotted literal to be detected: %q", dottedLiteral)
	}
}

func TestGenericAssignedSecretRejectsMemberReferences(t *testing.T) {
	cases := []string{
		`password = Bcrypt.HashPassword(userPassword);`,
		`password = _profileEditor.ChangePassword.ProfileData.Password;`,
		`password = settings.productionValue;`,
		`password = configuration.get("DATABASE_PASSWORD");`,
		`token: environmentVariables.currentValue;`,
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			for _, d := range DefaultRegistry() {
				for _, c := range d.Detect([]byte(tc)) {
					if c.DetectorID == "generic-assigned-secret" {
						t.Fatalf("expected member reference to be ignored, got %q from %q", c.Secret, tc)
					}
				}
			}
		})
	}
}

func TestFrontAPITokenRejectsPropertyChains(t *testing.T) {
	cases := []string{
		`plot.plugins.bubbleRenderer.highlightLabel`,
		`currentLine.ImportedPatientAccountId`,
		`front renderer uses plot.plugins.bubbleRenderer.highlightLabel`,
		`front import currentLine.ImportedPatientAccountId`,
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			for _, d := range DefaultRegistry() {
				for _, c := range d.Detect([]byte(tc)) {
					if c.DetectorID == "front-api-token" {
						t.Fatalf("expected property chain to be ignored, got %q from %q", c.Secret, tc)
					}
				}
			}
		})
	}
}

func TestBroadProviderContextStopsAtBlankLine(t *testing.T) {
	secret := strings.Repeat("A", 48)
	input := "cohere documentation\n\napi_key=\"" + secret + "\""
	if registryFinds("cohere-api-key", input, secret) {
		t.Fatal("expected blank line to separate provider context from assignment")
	}
	input = "cohere api_key=\"" + secret + "\""
	if !registryFinds("cohere-api-key", input, secret) {
		t.Fatal("expected same-line provider context to remain detectable")
	}
}

func TestSharedPrefixDetectorsRequireProviderContext(t *testing.T) {
	cases := []struct {
		id    string
		input string
	}{
		{"clerk-secret-key", "STRIPE_SECRET_KEY=sk_live_" + strings.Repeat("A", 32)},
		{"workos-api-key", "OTHER_API_KEY=sk_test_" + strings.Repeat("B", 32)},
		{"liveblocks-secret-key", "OTHER_SECRET=sk_prod_" + strings.Repeat("C", 32)},
		{"resend-api-key", "cache_value=re_" + strings.Repeat("D", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			for _, d := range DefaultRegistry() {
				for _, candidate := range d.Detect([]byte(tc.input)) {
					if candidate.DetectorID == tc.id {
						t.Fatalf("unexpected %s finding for %q", tc.id, tc.input)
					}
				}
			}
		})
	}
}

func TestLoadCustomFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.json")
	err := os.WriteFile(path, []byte(`{
		"detectors": [{
			"id": "internal",
			"name": "Internal",
			"keywords": ["internal_key"],
			"regex": "internal_key=([a-z0-9]{16})",
			"secret_group": 1
		}]
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	ds, err := LoadCustomFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 {
		t.Fatalf("expected one detector, got %d", len(ds))
	}
	candidates := ds[0].Detect([]byte("internal_key=abcdefghijklmnop"))
	if len(candidates) != 1 || candidates[0].Secret != "abcdefghijklmnop" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestLoadCustomFileRejectsInvalidConfiguration(t *testing.T) {
	cases := map[string]string{
		"invalid regex":    `{"detectors":[{"id":"bad","regex":"("}]}`,
		"unknown field":    `{"detectors":[{"id":"bad","regex":"x","extra":true}]}`,
		"invalid severity": `{"detectors":[{"id":"bad","regex":"x","severity":"urgent"}]}`,
		"invalid group":    `{"detectors":[{"id":"bad","regex":"(x)","secret_group":2}]}`,
		"duplicate id":     `{"detectors":[{"id":"same","regex":"x"},{"id":"same","regex":"y"}]}`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "detectors.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCustomFile(path); err == nil {
				t.Fatal("expected controlled configuration error")
			}
		})
	}
}

func TestConfigureRegistryControlsAndOverrides(t *testing.T) {
	registry := []Detector{
		NewRegex("one", "One", "low", nil, `(one-secret-value)`, 1, nil),
		NewRegex("two", "Two", "medium", nil, `(two-secret-value)`, 1, nil),
	}
	configured, err := ConfigureRegistry(registry, []string{"one"}, nil, map[string]string{"one": "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if len(configured) != 1 || configured[0].Info().ID != "one" || configured[0].Info().Severity != "critical" {
		t.Fatalf("unexpected configured registry: %#v", RegistryInfo(configured))
	}
	candidates := configured[0].Detect([]byte("one-secret-value"))
	if len(candidates) != 1 || candidates[0].Severity != "critical" {
		t.Fatalf("severity override not applied: %#v", candidates)
	}
	if _, err := ConfigureRegistry(append(registry, registry[0]), nil, nil, nil); err == nil {
		t.Fatal("expected duplicate registry ID error")
	}
	if _, err := ConfigureRegistry(registry, nil, []string{"missing"}, nil); err == nil {
		t.Fatal("expected unknown disabled detector error")
	}
}

func TestRegistryInfo(t *testing.T) {
	infos := RegistryInfo(DefaultRegistry())
	if len(infos) == 0 {
		t.Fatal("expected detector info")
	}
	if infos[0].ID == "" || infos[0].Name == "" || infos[0].Severity == "" {
		t.Fatalf("incomplete detector info: %#v", infos[0])
	}
}
