package githubapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNextLink(t *testing.T) {
	header := `<https://api.github.com/resource?page=2>; rel="next", <https://api.github.com/resource?page=5>; rel="last"`
	got := nextLink(header)
	if got != "https://api.github.com/resource?page=2" {
		t.Fatalf("unexpected next link: %q", got)
	}
}

func TestDedupeRepos(t *testing.T) {
	repos := dedupeRepos([]Repository{{FullName: "b/repo", CloneURL: "https://github.com/b/repo"}, {FullName: "a/repo", CloneURL: "https://github.com/a/repo"}, {FullName: "a/repo", CloneURL: "https://github.com/a/repo"}})
	if len(repos) != 2 {
		t.Fatalf("expected two repos, got %d", len(repos))
	}
	if repos[0].FullName != "a/repo" || repos[1].FullName != "b/repo" {
		t.Fatalf("repos not sorted/deduped: %#v", repos)
	}
}

func TestCreateAppJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "app.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	jwt, err := CreateAppJWT("12345", path, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(jwt, "."); len(parts) != 3 {
		t.Fatalf("expected three JWT parts, got %d: %s", len(parts), jwt)
	}
}

func TestInstallationForOrg(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/installation" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer app-jwt" {
			t.Fatalf("unexpected auth header: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(Installation{ID: 123})
	}))
	defer server.Close()

	client := New("app-jwt")
	client.baseURL = server.URL
	installation, err := client.InstallationForOrg(t.Context(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if installation.ID != 123 {
		t.Fatalf("unexpected installation ID: %d", installation.ID)
	}
}
