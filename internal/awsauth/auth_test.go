package awsauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSSOSettingsWithSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	contents := `[profile engineering]
sso_session = company
sso_account_id = 123456789012
sso_role_name = SecurityAudit

[sso-session company]
sso_start_url = https://example.awsapps.com/start
sso_region = eu-west-1
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSSOSettings(path, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if settings.StartURL != "https://example.awsapps.com/start" || settings.Region != "eu-west-1" || settings.AccountID != "123456789012" || settings.RoleName != "SecurityAudit" {
		t.Fatalf("unexpected settings: %#v", settings)
	}
}

func TestLoadSSOSettingsRejectsIncompleteProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("[default]\nsso_region = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSSOSettings(path, ""); err == nil {
		t.Fatal("expected incomplete profile error")
	}
}
