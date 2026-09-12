package azuredevops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Client struct {
	organization string
	baseURL      string
	authHeader   string
	http         *http.Client
}

type Project struct {
	Name string `json:"name"`
}

type Repository struct {
	Name     string `json:"name"`
	Project  string `json:"project"`
	CloneURL string `json:"clone_url"`
}

func New(organization, baseURL, authHeader string) *Client {
	organization = strings.TrimSpace(organization)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "https://dev.azure.com"
	}
	return &Client{organization: organization, baseURL: baseURL, authHeader: authHeader, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var projects []Project
	path := fmt.Sprintf("/%s/_apis/projects?api-version=7.1&$top=100", url.PathEscape(c.organization))
	for path != "" {
		var page struct {
			Value             []Project `json:"value"`
			ContinuationToken string    `json:"continuationToken"`
		}
		if err := c.get(ctx, c.baseURL+path, &page); err != nil {
			return nil, err
		}
		projects = append(projects, page.Value...)
		path = ""
		if page.ContinuationToken != "" {
			path = fmt.Sprintf("/%s/_apis/projects?api-version=7.1&$top=100&continuationToken=%s", url.PathEscape(c.organization), url.QueryEscape(page.ContinuationToken))
		}
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Name < projects[j].Name })
	return projects, nil
}

func (c *Client) Repositories(ctx context.Context, projects []string) ([]Repository, error) {
	if len(projects) == 0 {
		discovered, err := c.Projects(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Azure DevOps projects for %s: %w", c.organization, err)
		}
		for _, project := range discovered {
			projects = append(projects, project.Name)
		}
	}
	var repos []Repository
	for _, project := range projects {
		project = strings.TrimSpace(project)
		if project == "" {
			continue
		}
		path := fmt.Sprintf("/%s/%s/_apis/git/repositories?api-version=7.1", url.PathEscape(c.organization), url.PathEscape(project))
		var page struct {
			Value []struct {
				Name      string `json:"name"`
				RemoteURL string `json:"remoteUrl"`
				WebURL    string `json:"webUrl"`
			} `json:"value"`
		}
		if err := c.get(ctx, c.baseURL+path, &page); err != nil {
			return nil, fmt.Errorf("list Azure DevOps repos for %s/%s: %w", c.organization, project, err)
		}
		for _, repo := range page.Value {
			cloneURL := repo.RemoteURL
			if cloneURL == "" {
				cloneURL = repo.WebURL
			}
			if cloneURL == "" {
				continue
			}
			repos = append(repos, Repository{Name: repo.Name, Project: project, CloneURL: cloneURL})
		}
	}
	return dedupeRepos(repos), nil
}

func (c *Client) get(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.authHeader != "" {
		name, value, ok := strings.Cut(c.authHeader, ":")
		if ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("Azure DevOps API %s returned %s", endpoint, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func dedupeRepos(repos []Repository) []Repository {
	seen := map[string]struct{}{}
	out := make([]Repository, 0, len(repos))
	for _, repo := range repos {
		key := strings.ToLower(repo.CloneURL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, repo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CloneURL < out[j].CloneURL })
	return out
}
