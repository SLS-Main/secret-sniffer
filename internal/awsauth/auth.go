package awsauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/smithy-go"
)

type Options struct {
	Profile         string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	SSODeviceAuth   bool
	ConfigFile      string
	DevicePrompt    func(verificationURI, userCode string)
}

func Load(ctx context.Context, opts Options) (aws.Config, error) {
	if (opts.AccessKeyID == "") != (opts.SecretAccessKey == "") {
		return aws.Config{}, errors.New("both AWS access key ID and secret access key are required")
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{}
	if opts.Profile != "" {
		loadOptions = append(loadOptions, awsconfig.WithSharedConfigProfile(opts.Profile))
	}
	if opts.Region != "" {
		loadOptions = append(loadOptions, awsconfig.WithRegion(opts.Region))
	}
	if opts.AccessKeyID != "" {
		provider := credentials.NewStaticCredentialsProvider(opts.AccessKeyID, opts.SecretAccessKey, opts.SessionToken)
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(provider))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS configuration: %w", err)
	}
	if opts.SSODeviceAuth {
		settings, err := loadSSOSettings(opts.ConfigFile, opts.Profile)
		if err != nil {
			return aws.Config{}, err
		}
		provider, err := newDeviceProvider(ctx, cfg, settings, opts.DevicePrompt)
		if err != nil {
			return aws.Config{}, err
		}
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return aws.Config{}, fmt.Errorf("resolve AWS credentials: %w", err)
	}
	return cfg, nil
}

type ssoSettings struct {
	StartURL  string
	Region    string
	AccountID string
	RoleName  string
}

func loadSSOSettings(configPath, profile string) (ssoSettings, error) {
	if profile == "" {
		profile = "default"
	}
	if configPath == "" {
		configPath = os.Getenv("AWS_CONFIG_FILE")
	}
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ssoSettings{}, err
		}
		configPath = filepath.Join(home, ".aws", "config")
	}
	sections, err := readINI(configPath)
	if err != nil {
		return ssoSettings{}, fmt.Errorf("read AWS SSO profile: %w", err)
	}
	profileSection := profile
	if profile != "default" {
		profileSection = "profile " + profile
	}
	values := sections[profileSection]
	settings := ssoSettings{StartURL: values["sso_start_url"], Region: values["sso_region"], AccountID: values["sso_account_id"], RoleName: values["sso_role_name"]}
	if session := values["sso_session"]; session != "" {
		sessionValues := sections["sso-session "+session]
		settings.StartURL = sessionValues["sso_start_url"]
		settings.Region = sessionValues["sso_region"]
	}
	if settings.StartURL == "" || settings.Region == "" || settings.AccountID == "" || settings.RoleName == "" {
		return ssoSettings{}, fmt.Errorf("AWS profile %q must define sso_start_url, sso_region, sso_account_id, and sso_role_name (directly or through sso_session)", profile)
	}
	return settings, nil
}

func readINI(path string) (map[string]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sections := map[string]map[string]string{}
	section := ""
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if sections[section] == nil {
				sections[section] = map[string]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section != "" {
			sections[section][strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return sections, scan.Err()
}

type deviceProvider struct {
	mu            sync.Mutex
	sso           *sso.Client
	oidc          *ssooidc.Client
	clientID      string
	clientSecret  string
	accessToken   string
	refreshToken  string
	accessExpires time.Time
	accountID     string
	roleName      string
}

func newDeviceProvider(ctx context.Context, cfg aws.Config, settings ssoSettings, prompt func(string, string)) (*deviceProvider, error) {
	ssoCfg := cfg.Copy()
	ssoCfg.Region = settings.Region
	oidc := ssooidc.NewFromConfig(ssoCfg)
	registration, err := oidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("secret-sniffer"), ClientType: aws.String("public"), Scopes: []string{"sso:account:access"},
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
	})
	if err != nil {
		return nil, fmt.Errorf("register AWS SSO device client: %w", err)
	}
	authorization, err := oidc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId: registration.ClientId, ClientSecret: registration.ClientSecret, StartUrl: aws.String(settings.StartURL),
	})
	if err != nil {
		return nil, fmt.Errorf("start AWS SSO device authorization: %w", err)
	}
	if prompt != nil {
		verificationURI := aws.ToString(authorization.VerificationUriComplete)
		if verificationURI == "" {
			verificationURI = aws.ToString(authorization.VerificationUri)
		}
		prompt(verificationURI, aws.ToString(authorization.UserCode))
	}
	interval := time.Duration(authorization.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(authorization.ExpiresIn) * time.Second)
	var token *ssooidc.CreateTokenOutput
	for time.Now().Before(deadline) {
		if err := sleep(ctx, interval); err != nil {
			return nil, err
		}
		token, err = oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId: registration.ClientId, ClientSecret: registration.ClientSecret,
			DeviceCode: authorization.DeviceCode, GrantType: aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err == nil {
			break
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			return nil, fmt.Errorf("complete AWS SSO device authorization: %w", err)
		}
		switch apiErr.ErrorCode() {
		case "AuthorizationPendingException":
			continue
		case "SlowDownException":
			interval += 5 * time.Second
			continue
		default:
			return nil, fmt.Errorf("complete AWS SSO device authorization: %w", err)
		}
	}
	if token == nil || token.AccessToken == nil {
		return nil, errors.New("AWS SSO device authorization expired before completion")
	}
	return &deviceProvider{
		sso: sso.NewFromConfig(ssoCfg), oidc: oidc, clientID: aws.ToString(registration.ClientId), clientSecret: aws.ToString(registration.ClientSecret),
		accessToken: aws.ToString(token.AccessToken), refreshToken: aws.ToString(token.RefreshToken), accessExpires: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		accountID: settings.AccountID, roleName: settings.RoleName,
	}, nil
}

func (p *deviceProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Now().After(p.accessExpires.Add(-time.Minute)) {
		if p.refreshToken == "" {
			return aws.Credentials{}, errors.New("AWS SSO access token expired; repeat device authentication")
		}
		token, err := p.oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId: aws.String(p.clientID), ClientSecret: aws.String(p.clientSecret),
			GrantType: aws.String("refresh_token"), RefreshToken: aws.String(p.refreshToken),
		})
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("refresh AWS SSO access token: %w", err)
		}
		p.accessToken = aws.ToString(token.AccessToken)
		if token.RefreshToken != nil {
			p.refreshToken = aws.ToString(token.RefreshToken)
		}
		p.accessExpires = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	out, err := p.sso.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(p.accessToken), AccountId: aws.String(p.accountID), RoleName: aws.String(p.roleName),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("get AWS SSO role credentials: %w", err)
	}
	if out.RoleCredentials == nil {
		return aws.Credentials{}, errors.New("AWS SSO returned no role credentials")
	}
	creds := out.RoleCredentials
	return aws.Credentials{
		AccessKeyID: aws.ToString(creds.AccessKeyId), SecretAccessKey: aws.ToString(creds.SecretAccessKey), SessionToken: aws.ToString(creds.SessionToken),
		Source: "SSODeviceAuth", CanExpire: true, Expires: time.UnixMilli(creds.Expiration),
	}, nil
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
