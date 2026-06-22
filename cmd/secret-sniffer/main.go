package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"secret-sniffer/internal/baseline"
	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/githubapi"
	"secret-sniffer/internal/output"
	"secret-sniffer/internal/parity"
	"secret-sniffer/internal/scanner"
)

func main() {
	var cfg scanner.Config
	var customPath string
	var format string
	var outputPath string
	var outputFlushFindings int
	var include string
	var exclude string
	var baselinePath string
	var writeBaselinePath string
	var summaryOutputPath string
	var githubOrgs string
	var githubEnterprise string
	var githubToken string
	var githubAppID string
	var githubAppPrivateKey string
	var githubInstallationID string
	var showVersion bool
	var listDetectors bool
	var truffleHogParity bool
	var githubAccessible bool
	var failOnFindings bool
	var redact bool
	var noRedact bool
	var quiet bool

	flag.StringVar(&cfg.Target, "target", ".", "local path or GitHub repository URL to scan")
	flag.IntVar(&cfg.Workers, "workers", runtime.NumCPU(), "number of concurrent workers")
	flag.Int64Var(&cfg.MaxFileBytes, "max-file-bytes", 25*1024*1024, "maximum file size to scan")
	flag.BoolVar(&cfg.GitHistory, "git-history", false, "scan every reachable git blob")
	flag.BoolVar(&cfg.Verify, "verify", false, "attempt live verification for supported detectors")
	flag.StringVar(&include, "include", "", "comma-separated glob patterns to include")
	flag.StringVar(&exclude, "exclude", "", "comma-separated glob patterns to exclude")
	flag.StringVar(&format, "format", "human", "output format: human, json, jsonl, sarif")
	flag.StringVar(&outputPath, "output", "", "stream findings to this JSONL file as they are discovered")
	flag.IntVar(&outputFlushFindings, "output-flush-findings", 25, "fsync streamed output after this many findings")
	flag.StringVar(&customPath, "custom-detectors", "", "path to custom detector JSON")
	flag.StringVar(&baselinePath, "baseline", "", "path to baseline JSON of accepted fingerprints")
	flag.StringVar(&writeBaselinePath, "write-baseline", "", "write finding fingerprints to baseline JSON")
	flag.StringVar(&summaryOutputPath, "summary-output", "", "write GitHub discovery and scan summary JSON to this path")
	flag.StringVar(&githubOrgs, "github-org", "", "comma-separated GitHub organization names to enumerate and scan")
	flag.StringVar(&githubEnterprise, "github-enterprise", "", "GitHub Enterprise Cloud slug; enumerate orgs and scan all repos")
	flag.StringVar(&githubToken, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for API enumeration and private clones; defaults to GITHUB_TOKEN")
	flag.StringVar(&githubAppID, "github-app-id", os.Getenv("GITHUB_APP_ID"), "GitHub App ID for minting installation tokens; defaults to GITHUB_APP_ID")
	flag.StringVar(&githubAppPrivateKey, "github-app-private-key", os.Getenv("GITHUB_APP_PRIVATE_KEY"), "path to GitHub App private key PEM; defaults to GITHUB_APP_PRIVATE_KEY")
	flag.StringVar(&githubInstallationID, "github-installation-id", os.Getenv("GITHUB_INSTALLATION_ID"), "optional GitHub App installation ID; defaults to GITHUB_INSTALLATION_ID")
	flag.BoolVar(&githubAccessible, "github-accessible", false, "scan all repositories accessible to the GitHub token")
	flag.BoolVar(&listDetectors, "list-detectors", false, "print detector metadata as JSON and exit")
	flag.BoolVar(&truffleHogParity, "trufflehog-parity", false, "print tracked TruffleHog detector parity mappings as JSON and exit")
	flag.BoolVar(&failOnFindings, "fail-on-findings", false, "exit with status 2 when findings are present")
	flag.BoolVar(&redact, "redact", false, "omit raw secrets from machine-readable output")
	flag.BoolVar(&noRedact, "no-redact", true, "include raw secrets in machine-readable output; default true")
	flag.BoolVar(&quiet, "quiet", false, "suppress progress logs on stderr")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Parse()

	if showVersion {
		fmt.Println("secret-sniffer dev")
		return
	}

	registry := detectors.DefaultRegistry()
	if customPath != "" {
		custom, err := detectors.LoadCustomFile(customPath)
		if err != nil {
			fatal(err)
		}
		registry = append(registry, custom...)
	}
	if listDetectors {
		if err := output.WriteDetectorInfo(os.Stdout, detectors.RegistryInfo(registry)); err != nil {
			fatal(err)
		}
		return
	}
	if truffleHogParity {
		if err := output.WriteJSON(os.Stdout, parity.CurrentReport()); err != nil {
			fatal(err)
		}
		return
	}

	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	cfg.Include = splitCSV(include)
	cfg.Exclude = splitCSV(exclude)
	runtime.GOMAXPROCS(cfg.Workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	logf(quiet, "secret-sniffer: starting scan")
	githubClients, err := githubClients(ctx, githubToken, githubAppID, githubAppPrivateKey, githubInstallationID, githubAccessible)
	if err != nil {
		fatal(err)
	}
	targets, tokenByTarget, tokenExpiryByTarget, installationByTarget, summary, err := scanTargets(ctx, cfg.Target, githubOrgs, githubEnterprise, githubAccessible, githubClients, quiet)
	if err != nil {
		fatal(err)
	}
	printDiscoverySummary(quiet, summary)
	logf(quiet, "secret-sniffer: scanning %d target(s) with %d worker(s) per target", len(targets), cfg.Workers)
	includeSecrets := noRedact && !redact
	var outputFile *os.File
	if outputPath != "" {
		outputFile, err = os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fatal(err)
		}
		defer outputFile.Close()
		logf(quiet, "secret-sniffer: streaming findings to %s", outputPath)
	}
	var knownBaseline map[string]struct{}
	if baselinePath != "" {
		logf(quiet, "secret-sniffer: loading baseline %s", baselinePath)
		knownBaseline, err = baseline.Load(baselinePath)
		if err != nil {
			fatal(err)
		}
	}
	var findings []detectors.Finding
	totalBeforeBaseline := 0
	totalAfterBaseline := 0
	streamedSinceSync := 0
	for i, target := range targets {
		logf(quiet, "secret-sniffer: [%d/%d] scanning %s", i+1, len(targets), target)
		targetCfg := cfg
		targetCfg.Target = target
		targetCfg.GitHubToken = tokenByTarget[target]
		if installationID := installationByTarget[target]; installationID > 0 && githubAppID != "" && githubAppPrivateKey != "" && shouldRefreshToken(tokenExpiryByTarget[target], time.Now()) {
			refreshed, err := refreshInstallationToken(ctx, githubAppID, githubAppPrivateKey, installationID)
			if err != nil {
				fatal(fmt.Errorf("refresh github installation token for %s: %w", target, err))
			}
			targetCfg.GitHubToken = refreshed.Token
			tokenByTarget[target] = refreshed.Token
			tokenExpiryByTarget[target] = refreshed.ExpiresAt
			logf(quiet, "secret-sniffer: [%d/%d] refreshed GitHub App installation token, expires=%s", i+1, len(targets), refreshed.ExpiresAt.Format(time.RFC3339))
		}
		runner := scanner.New(targetCfg, registry)
		targetFindings, err := runner.Scan(ctx)
		if err != nil {
			fatal(err)
		}
		totalBeforeBaseline += len(targetFindings)
		if knownBaseline != nil {
			targetFindings = baseline.Filter(targetFindings, knownBaseline)
		}
		totalAfterBaseline += len(targetFindings)
		logf(quiet, "secret-sniffer: [%d/%d] finished %s, findings=%d", i+1, len(targets), target, len(targetFindings))
		summary.addScanResult(target, len(targetFindings))
		for _, finding := range targetFindings {
			if err := output.WriteFindingHuman(os.Stderr, finding); err != nil {
				fatal(err)
			}
			if outputFile != nil {
				if err := output.WriteFindingJSONL(outputFile, finding, includeSecrets); err != nil {
					fatal(err)
				}
				streamedSinceSync++
				if outputFlushFindings < 1 || streamedSinceSync >= outputFlushFindings {
					if err := outputFile.Sync(); err != nil {
						fatal(err)
					}
					streamedSinceSync = 0
				}
			}
		}
		if outputFile != nil && streamedSinceSync > 0 {
			if err := outputFile.Sync(); err != nil {
				fatal(err)
			}
			streamedSinceSync = 0
		}
		if outputFile == nil || strings.ToLower(format) != "jsonl" || writeBaselinePath != "" {
			findings = append(findings, targetFindings...)
		}
	}
	if writeBaselinePath != "" {
		if err := baseline.Write(writeBaselinePath, findings); err != nil {
			fatal(err)
		}
	}
	summary.FindingsBeforeBaseline = totalBeforeBaseline
	summary.FindingsAfterBaseline = totalAfterBaseline
	printScanSummary(quiet, summary)
	if summaryOutputPath != "" {
		if err := writeSummary(summaryOutputPath, summary); err != nil {
			fatal(err)
		}
		logf(quiet, "secret-sniffer: wrote summary to %s", summaryOutputPath)
	}

	meta := output.Meta{Target: strings.Join(targets, ","), StartedAt: start, Duration: time.Since(start), Findings: totalAfterBaseline}
	if outputFile == nil || strings.ToLower(format) != "jsonl" {
		if err := output.Write(os.Stdout, strings.ToLower(format), findings, meta, includeSecrets); err != nil {
			fatal(err)
		}
	} else {
		fmt.Fprintf(os.Stdout, "scan complete: %d findings in %s\n", summary.FindingsAfterBaseline, time.Since(start).Round(time.Millisecond))
	}
	logf(quiet, "secret-sniffer: complete, findings=%d, duration=%s", totalAfterBaseline, time.Since(start).Round(time.Millisecond))
	if failOnFindings && totalAfterBaseline > 0 {
		os.Exit(2)
	}
}

type githubClient struct {
	client         *githubapi.Client
	token          string
	tokenExpiresAt time.Time
	installationID int64
}

type discoverySummary struct {
	Enterprise             string       `json:"enterprise,omitempty"`
	RequestedOrgs          []string     `json:"requested_orgs,omitempty"`
	Accessible             bool         `json:"accessible"`
	TotalRepositories      int          `json:"total_repositories"`
	FindingsBeforeBaseline int          `json:"findings_before_baseline"`
	FindingsAfterBaseline  int          `json:"findings_after_baseline"`
	Orgs                   []orgSummary `json:"orgs"`
}

type orgSummary struct {
	Name         string `json:"name"`
	Repositories int    `json:"repositories"`
	Findings     int    `json:"findings"`
}

func githubClients(ctx context.Context, token, appID, privateKeyPath, installationIDRaw string, allInstallations bool) ([]githubClient, error) {
	if appID == "" && privateKeyPath == "" {
		return []githubClient{{client: githubapi.New(token), token: token}}, nil
	}
	if appID == "" || privateKeyPath == "" {
		return nil, fmt.Errorf("both --github-app-id and --github-app-private-key are required for GitHub App auth")
	}
	if allInstallations && installationIDRaw == "" {
		jwt, err := githubapi.CreateAppJWT(appID, privateKeyPath, time.Now())
		if err != nil {
			return nil, err
		}
		appClient := githubapi.New(jwt)
		installations, err := appClient.Installations(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]githubClient, 0, len(installations))
		for _, installation := range installations {
			token, err := appClient.InstallationToken(ctx, installation.ID)
			if err != nil {
				return nil, fmt.Errorf("mint installation token for %s/%d: %w", installation.Account.Login, installation.ID, err)
			}
			out = append(out, githubClient{client: githubapi.New(token.Token), token: token.Token, tokenExpiresAt: token.ExpiresAt, installationID: installation.ID})
		}
		return out, nil
	}
	var installationID int64
	if installationIDRaw != "" {
		id, err := strconv.ParseInt(installationIDRaw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid --github-installation-id: %w", err)
		}
		installationID = id
	} else {
		jwt, err := githubapi.CreateAppJWT(appID, privateKeyPath, time.Now())
		if err != nil {
			return nil, err
		}
		appClient := githubapi.New(jwt)
		installations, err := appClient.Installations(ctx)
		if err != nil {
			return nil, err
		}
		if len(installations) != 1 {
			return nil, fmt.Errorf("github app has %d installations; provide --github-installation-id or use --github-accessible to scan all installations", len(installations))
		}
		installationID = installations[0].ID
	}
	installationToken, err := refreshInstallationToken(ctx, appID, privateKeyPath, installationID)
	if err != nil {
		return nil, err
	}
	return []githubClient{{client: githubapi.New(installationToken.Token), token: installationToken.Token, tokenExpiresAt: installationToken.ExpiresAt, installationID: installationID}}, nil
}

func scanTargets(ctx context.Context, target, orgs, enterprise string, accessible bool, clients []githubClient, quiet bool) ([]string, map[string]string, map[string]time.Time, map[string]int64, discoverySummary, error) {
	var targets []string
	tokens := map[string]string{}
	expires := map[string]time.Time{}
	installations := map[string]int64{}
	summary := discoverySummary{Enterprise: enterprise, RequestedOrgs: splitCSV(orgs), Accessible: accessible, Orgs: []orgSummary{}}
	for _, org := range splitCSV(orgs) {
		logf(quiet, "secret-sniffer: discovering repositories for GitHub org %s", org)
		for _, gc := range clients {
			repos, err := gc.client.RepositoriesForOrg(ctx, org)
			if err != nil {
				return nil, nil, nil, nil, summary, err
			}
			logf(quiet, "secret-sniffer: discovered %d repositories for org %s", len(repos), org)
			addRepos(&targets, tokens, expires, installations, repos, gc)
			summary.addRepos(repos)
		}
	}
	if enterprise != "" {
		logf(quiet, "secret-sniffer: discovering repositories for GitHub enterprise %s", enterprise)
		for _, gc := range clients {
			repos, err := gc.client.RepositoriesForEnterprise(ctx, enterprise)
			if err != nil {
				return nil, nil, nil, nil, summary, err
			}
			logf(quiet, "secret-sniffer: discovered %d repositories for enterprise %s", len(repos), enterprise)
			addRepos(&targets, tokens, expires, installations, repos, gc)
			summary.addRepos(repos)
		}
	}
	if accessible {
		logf(quiet, "secret-sniffer: discovering all repositories accessible to GitHub credential(s)")
		for _, gc := range clients {
			repos, err := gc.client.AccessibleRepositories(ctx)
			if err != nil {
				return nil, nil, nil, nil, summary, err
			}
			logf(quiet, "secret-sniffer: discovered %d accessible repositories", len(repos))
			addRepos(&targets, tokens, expires, installations, repos, gc)
			summary.addRepos(repos)
		}
	}
	if len(targets) == 0 {
		targets = append(targets, target)
		if len(clients) > 0 {
			tokens[target] = clients[0].token
			expires[target] = clients[0].tokenExpiresAt
			installations[target] = clients[0].installationID
		}
	}
	targets = dedupeStrings(targets)
	summary.TotalRepositories = len(targets)
	summary.sortOrgs()
	return targets, tokens, expires, installations, summary, nil
}

func logf(quiet bool, format string, args ...any) {
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func addRepos(targets *[]string, tokens map[string]string, expires map[string]time.Time, installations map[string]int64, repos []githubapi.Repository, gc githubClient) {
	for _, repo := range repos {
		if repo.CloneURL != "" {
			*targets = append(*targets, repo.CloneURL)
			tokens[repo.CloneURL] = gc.token
			expires[repo.CloneURL] = gc.tokenExpiresAt
			installations[repo.CloneURL] = gc.installationID
		}
	}
}

func refreshInstallationToken(ctx context.Context, appID, privateKeyPath string, installationID int64) (githubapi.InstallationToken, error) {
	appClient, err := githubapi.NewGitHubAppJWTClient(appID, privateKeyPath)
	if err != nil {
		return githubapi.InstallationToken{}, err
	}
	return appClient.InstallationToken(ctx, installationID)
}

func shouldRefreshToken(expiresAt, now time.Time) bool {
	if expiresAt.IsZero() {
		return true
	}
	return now.After(expiresAt.Add(-10 * time.Minute))
}

func dedupeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (s *discoverySummary) addRepos(repos []githubapi.Repository) {
	counts := map[string]int{}
	for _, repo := range repos {
		owner := repoOwner(repo)
		if owner == "" {
			continue
		}
		counts[owner]++
	}
	for org, count := range counts {
		s.addOrgRepos(org, count)
	}
}

func (s *discoverySummary) addOrgRepos(name string, count int) {
	for i := range s.Orgs {
		if s.Orgs[i].Name == name {
			s.Orgs[i].Repositories += count
			return
		}
	}
	s.Orgs = append(s.Orgs, orgSummary{Name: name, Repositories: count})
}

func (s *discoverySummary) addScanResult(target string, findings int) {
	s.FindingsBeforeBaseline += findings
	owner := targetOwner(target)
	for i := range s.Orgs {
		if s.Orgs[i].Name == owner {
			s.Orgs[i].Findings += findings
			return
		}
	}
	if owner != "" {
		s.Orgs = append(s.Orgs, orgSummary{Name: owner, Findings: findings})
	}
}

func (s *discoverySummary) sortOrgs() {
	slices.SortFunc(s.Orgs, func(a, b orgSummary) int { return strings.Compare(a.Name, b.Name) })
}

func repoOwner(repo githubapi.Repository) string {
	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) == 2 {
		return parts[0]
	}
	return ""
}

func targetOwner(target string) string {
	u, err := url.Parse(target)
	if err == nil && strings.EqualFold(u.Host, "github.com") {
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

func printDiscoverySummary(quiet bool, summary discoverySummary) {
	if quiet || summary.TotalRepositories == 0 || len(summary.Orgs) == 0 {
		return
	}
	if summary.Enterprise != "" {
		logf(false, "secret-sniffer: enterprise %s discovery summary", summary.Enterprise)
	} else if summary.Accessible {
		logf(false, "secret-sniffer: accessible repository discovery summary")
	} else {
		logf(false, "secret-sniffer: organization discovery summary")
	}
	logf(false, "secret-sniffer: orgs=%d repos=%d", len(summary.Orgs), summary.TotalRepositories)
	for _, org := range summary.Orgs {
		logf(false, "secret-sniffer:   %s repos=%d", org.Name, org.Repositories)
	}
}

func printScanSummary(quiet bool, summary discoverySummary) {
	if quiet || summary.TotalRepositories == 0 {
		return
	}
	logf(false, "secret-sniffer: scan summary repos=%d findings_before_baseline=%d findings_after_baseline=%d", summary.TotalRepositories, summary.FindingsBeforeBaseline, summary.FindingsAfterBaseline)
	for _, org := range summary.Orgs {
		logf(false, "secret-sniffer:   %s repos=%d findings=%d", org.Name, org.Repositories, org.Findings)
	}
}

func writeSummary(path string, summary discoverySummary) error {
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "secret-sniffer: %v\n", err)
	os.Exit(1)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
