package githubapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type Repository struct {
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
}

type org struct {
	Login string `json:"login"`
}

type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
}

type InstallationToken struct {
	Token     string
	ExpiresAt time.Time
}

func New(token string) *Client {
	return &Client{baseURL: "https://api.github.com", token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Token() string {
	return c.token
}

func NewGitHubAppClient(ctx context.Context, appID, privateKeyPath string, installationID int64) (*Client, error) {
	jwt, err := CreateAppJWT(appID, privateKeyPath, time.Now())
	if err != nil {
		return nil, err
	}
	appClient := New(jwt)
	if installationID == 0 {
		installations, err := appClient.Installations(ctx)
		if err != nil {
			return nil, err
		}
		if len(installations) != 1 {
			return nil, fmt.Errorf("github app has %d installations; provide --github-installation-id or use --github-accessible to scan all installations", len(installations))
		}
		installationID = installations[0].ID
	}
	token, err := appClient.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	return New(token.Token), nil
}

func NewGitHubAppInstallationClients(ctx context.Context, appID, privateKeyPath string) ([]*Client, error) {
	jwt, err := CreateAppJWT(appID, privateKeyPath, time.Now())
	if err != nil {
		return nil, err
	}
	appClient := New(jwt)
	installations, err := appClient.Installations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Client, 0, len(installations))
	for _, installation := range installations {
		token, err := appClient.InstallationToken(ctx, installation.ID)
		if err != nil {
			return nil, fmt.Errorf("mint installation token for %s/%d: %w", installation.Account.Login, installation.ID, err)
		}
		out = append(out, New(token.Token))
	}
	return out, nil
}

func (c *Client) Installations(ctx context.Context) ([]Installation, error) {
	var installations []Installation
	next := c.baseURL + "/app/installations?per_page=100"
	for next != "" {
		var page []Installation
		link, err := c.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		installations = append(installations, page...)
		next = nextLink(link)
	}
	return installations, nil
}

func (c *Client) InstallationForOrg(ctx context.Context, org string) (Installation, error) {
	var installation Installation
	_, err := c.get(ctx, c.baseURL+fmt.Sprintf("/orgs/%s/installation", url.PathEscape(org)), &installation)
	if err != nil {
		return Installation{}, err
	}
	return installation, nil
}

func (c *Client) InstallationToken(ctx context.Context, installationID int64) (InstallationToken, error) {
	endpoint := c.baseURL + fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return InstallationToken{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return InstallationToken{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return InstallationToken{}, fmt.Errorf("github api %s returned %s", endpoint, resp.Status)
	}
	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return InstallationToken{}, err
	}
	if body.Token == "" {
		return InstallationToken{}, errors.New("github returned empty installation token")
	}
	return InstallationToken{Token: body.Token, ExpiresAt: body.ExpiresAt}, nil
}

func NewGitHubAppJWTClient(appID, privateKeyPath string) (*Client, error) {
	jwt, err := CreateAppJWT(appID, privateKeyPath, time.Now())
	if err != nil {
		return nil, err
	}
	return New(jwt), nil
}

func CreateAppJWT(appID, privateKeyPath string, now time.Time) (string, error) {
	key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return "", err
	}
	header := base64RawURL([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + base64RawURL(payload)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64RawURL(sig), nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Client) RepositoriesForOrg(ctx context.Context, name string) ([]Repository, error) {
	path := fmt.Sprintf("/orgs/%s/repos?type=all&per_page=100", url.PathEscape(name))
	return c.paginateRepos(ctx, path)
}

func (c *Client) RepositoriesForEnterprise(ctx context.Context, enterprise string) ([]Repository, error) {
	orgs, err := c.enterpriseOrgs(ctx, enterprise)
	if err != nil {
		return nil, err
	}
	var repos []Repository
	for _, o := range orgs {
		rs, err := c.RepositoriesForOrg(ctx, o.Login)
		if err != nil {
			return nil, fmt.Errorf("list repos for org %s: %w", o.Login, err)
		}
		repos = append(repos, rs...)
	}
	return dedupeRepos(repos), nil
}

func (c *Client) AccessibleRepositories(ctx context.Context) ([]Repository, error) {
	installationRepos, err := c.installationRepositories(ctx)
	if err == nil && len(installationRepos) > 0 {
		return dedupeRepos(installationRepos), nil
	}
	userRepos, userErr := c.paginateRepos(ctx, "/user/repos?affiliation=owner,collaborator,organization_member&visibility=all&per_page=100")
	if userErr != nil {
		if err != nil {
			return nil, fmt.Errorf("list accessible repositories via installation API failed: %v; user repo API failed: %w", err, userErr)
		}
		return nil, userErr
	}
	return dedupeRepos(userRepos), nil
}

func (c *Client) installationRepositories(ctx context.Context) ([]Repository, error) {
	type response struct {
		Repositories []Repository `json:"repositories"`
	}
	var repos []Repository
	next := c.baseURL + "/installation/repositories?per_page=100"
	for next != "" {
		var r response
		link, err := c.get(ctx, next, &r)
		if err != nil {
			return nil, err
		}
		repos = append(repos, r.Repositories...)
		next = nextLink(link)
	}
	return repos, nil
}

func (c *Client) enterpriseOrgs(ctx context.Context, enterprise string) ([]org, error) {
	var out []org
	next := c.baseURL + fmt.Sprintf("/enterprises/%s/orgs?per_page=100", url.PathEscape(enterprise))
	for next != "" {
		var page []org
		link, err := c.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		next = nextLink(link)
	}
	return out, nil
}

func (c *Client) paginateRepos(ctx context.Context, path string) ([]Repository, error) {
	var repos []Repository
	next := c.baseURL + path
	for next != "" {
		var page []Repository
		link, err := c.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		repos = append(repos, page...)
		next = nextLink(link)
	}
	return dedupeRepos(repos), nil
}

func (c *Client) get(ctx context.Context, endpoint string, v any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("github api %s returned %s", endpoint, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return "", err
	}
	return resp.Header.Get("Link"), nil
}

func nextLink(linkHeader string) string {
	for _, part := range strings.Split(linkHeader, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start {
			return part[start+1 : end]
		}
	}
	return ""
}

func dedupeRepos(repos []Repository) []Repository {
	seen := map[string]Repository{}
	for _, r := range repos {
		if r.CloneURL == "" || r.FullName == "" {
			continue
		}
		seen[r.FullName] = r
	}
	out := make([]Repository, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out
}
