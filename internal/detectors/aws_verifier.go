package detectors

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func verifyAWSCredentials(ctx context.Context, candidate Candidate) VerificationResult {
	accessKeyID := candidate.SecretParts["access_key_id"]
	secretAccessKey := candidate.SecretParts["secret_access_key"]
	sessionToken := candidate.SecretParts["session_token"]
	if accessKeyID == "" || secretAccessKey == "" {
		return invalidCredentialResult()
	}
	if strings.HasPrefix(accessKeyID, "ASIA") && sessionToken == "" {
		return VerificationResult{Status: VerificationUnsupported, Message: "temporary AWS credentials require a session token"}
	}

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
	if client := verificationHTTPClient(ctx); client != nil {
		cfg.HTTPClient = client
	}
	_, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err == nil {
		return VerificationResult{Status: VerificationVerified}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return unknownVerificationResult("timeout", "provider request timed out")
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return unknownVerificationResult("cancelled", "provider request cancelled")
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return unknownVerificationResult("network", "provider request failed")
	}
	switch strings.ToLower(apiErr.ErrorCode()) {
	case "invalidclienttokenid", "signaturedoesnotmatch", "expiredtoken", "expiredtokenexception", "unrecognizedclientexception":
		return invalidCredentialResult()
	case "throttling", "throttlingexception", "toomanyrequestsexception", "requestlimitexceeded":
		return unknownVerificationResult("rate_limited", "provider rate limited verification")
	case "requestexpired", "requesttimeskewed", "requesttimetoolskewed":
		return unknownVerificationResult("clock_skew", "provider could not verify the request timestamp")
	case "accessdenied", "accessdeniedexception", "unauthorizedoperation":
		return unknownVerificationResult("authorization", "provider denied account access")
	default:
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response")
	}
}
