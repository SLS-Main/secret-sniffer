package azuredevops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRepositoriesDiscoversProjectsAndRepos(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/org/_apis/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[{"name":"Project One"}]}`))
		case "/org/Project One/_apis/git/repositories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[{"name":"repo","remoteUrl":"https://dev.azure.com/org/Project%20One/_git/repo"}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := New("org", server.URL, "Authorization: Bearer token")
	repos, err := client.Repositories(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].Project != "Project One" || repos[0].CloneURL != "https://dev.azure.com/org/Project%20One/_git/repo" {
		t.Fatalf("repos=%#v", repos)
	}
}

func TestRepositoriesUsesSelectedProjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/org/Project/_apis/git/repositories" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"name":"repo","remoteUrl":"https://example.test/repo"}]}`))
	}))
	defer server.Close()

	client := New("org", server.URL, "")
	repos, err := client.Repositories(context.Background(), []string{"Project"})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].CloneURL != "https://example.test/repo" {
		t.Fatalf("repos=%#v", repos)
	}
}
