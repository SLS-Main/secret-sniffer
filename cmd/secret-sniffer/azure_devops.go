package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"secret-sniffer/internal/azuredevops"
)

const azureDevOpsScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"

type azureDevOpsOptions struct {
	Organizations        []string
	Projects             []string
	BaseURL              string
	Auth                 string
	PAT                  string
	BearerToken          string
	TenantID             string
	ClientID             string
	ClientSecret         string
	ClientCertificate    string
	ClientCertPassword   string
	FederatedTokenFile   string
	ManagedIdentityID    string
	RepositoryListOnly   bool
	Console              console
	TokenRefreshInterval time.Duration
}

func discoverAzureDevOpsRepositories(ctx context.Context, opts azureDevOpsOptions) ([]string, map[string]string, error) {
	if len(opts.Organizations) == 0 {
		return nil, nil, nil
	}
	header, err := azureDevOpsAuthHeader(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	var targets []string
	authHeaders := map[string]string{}
	for _, org := range opts.Organizations {
		org = strings.TrimSpace(org)
		if org == "" {
			continue
		}
		opts.Console.info("Discovering Azure DevOps repositories for organization %s", org)
		client := azuredevops.New(org, opts.BaseURL, header)
		repos, err := client.Repositories(ctx, opts.Projects)
		if err != nil {
			return nil, nil, err
		}
		opts.Console.info("Discovered %d Azure DevOps repositories for organization %s", len(repos), org)
		for _, repo := range repos {
			targets = append(targets, repo.CloneURL)
			if header != "" {
				authHeaders[repo.CloneURL] = header
			}
		}
	}
	targets = dedupeStrings(targets)
	return targets, authHeaders, nil
}

func azureDevOpsAuthHeader(ctx context.Context, opts azureDevOpsOptions) (string, error) {
	mode := azureDevOpsAuthMode(opts)
	if err := validateAzureDevOpsAuthMode(mode); err != nil {
		return "", err
	}
	switch mode {
	case "pat":
		if opts.PAT == "" {
			return "", errors.New("--azure-devops-pat is required for Azure DevOps PAT auth")
		}
		return "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":"+opts.PAT)), nil
	case "bearer":
		if opts.BearerToken == "" {
			return "", errors.New("--azure-devops-token is required for Azure DevOps bearer auth")
		}
		return "Authorization: Bearer " + opts.BearerToken, nil
	case "anonymous":
		return "", nil
	default:
		cred, err := azureTokenCredential(mode, azureRunOptions{
			TenantID: opts.TenantID, ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
			ClientCertificate: opts.ClientCertificate, ClientCertPassword: opts.ClientCertPassword,
			FederatedTokenFile: opts.FederatedTokenFile, ManagedIdentityID: opts.ManagedIdentityID,
		})
		if err != nil {
			return "", err
		}
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureDevOpsScope}})
		if err != nil {
			return "", fmt.Errorf("get Azure DevOps token: %w", err)
		}
		return "Authorization: Bearer " + token.Token, nil
	}
}

func azureDevOpsAuthMode(opts azureDevOpsOptions) string {
	if opts.Auth != "" {
		return strings.ToLower(strings.TrimSpace(opts.Auth))
	}
	switch {
	case opts.PAT != "":
		return "pat"
	case opts.BearerToken != "":
		return "bearer"
	default:
		return "default"
	}
}

func validateAzureDevOpsAuthMode(mode string) error {
	switch mode {
	case "default", "client-secret", "client-certificate", "managed-identity", "workload-identity", "azure-cli", "azure-dev-cli", "pat", "bearer", "anonymous":
		return nil
	default:
		return fmt.Errorf("unknown Azure DevOps auth mode %q", mode)
	}
}

func azureDevOpsAuthModeUsesAAD(mode string) bool {
	switch mode {
	case "default", "client-secret", "client-certificate", "managed-identity", "workload-identity", "azure-cli", "azure-dev-cli":
		return true
	default:
		return false
	}
}
