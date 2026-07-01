package main

import (
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	var repoConcurrency int
	var include string
	var exclude string
	var baselinePath string
	var writeBaselinePath string
	var summaryOutputPath string
	var scanJobID string
	var scanJobPath string
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
	var summaryOnly bool
	var scanResume bool
	var scanRetryFailed bool
	var failOnFindings bool
	var redact bool
	var noRedact bool
	var quiet bool
	var noColor bool

	flag.StringVar(&cfg.Target, "target", ".", "local path or GitHub repository URL to scan")
	flag.IntVar(&cfg.Workers, "workers", runtime.NumCPU(), "number of concurrent workers")
	flag.Int64Var(&cfg.MaxFileBytes, "max-file-bytes", 25*1024*1024, "maximum file size to scan")
	flag.BoolVar(&cfg.ScanArchives, "scan-archives", false, "scan supported archives in memory: zip, tar, tar.gz, tgz, gz")
	flag.IntVar(&cfg.MaxArchiveDepth, "max-archive-depth", 2, "maximum nested archive depth when --scan-archives is enabled")
	flag.IntVar(&cfg.MaxArchiveEntries, "max-archive-entries", 10000, "maximum entries to inspect per archive when --scan-archives is enabled")
	flag.Int64Var(&cfg.MaxArchiveBytes, "max-archive-bytes", 250*1024*1024, "maximum expanded bytes to inspect per archive when --scan-archives is enabled")
	flag.Int64Var(&cfg.MaxExpandedFileBytes, "max-expanded-file-bytes", 25*1024*1024, "maximum decompressed archive entry size to scan")
	flag.BoolVar(&cfg.GitHistory, "git-history", false, "scan every reachable git blob")
	flag.BoolVar(&cfg.Verify, "verify", false, "attempt live verification for supported detectors")
	flag.StringVar(&include, "include", "", "comma-separated glob patterns to include")
	flag.StringVar(&exclude, "exclude", "", "comma-separated glob patterns to exclude")
	flag.StringVar(&format, "format", "human", "output format: human, json, jsonl, sarif")
	flag.StringVar(&outputPath, "output", "", "stream findings to this JSONL file as they are discovered")
	flag.IntVar(&outputFlushFindings, "output-flush-findings", 25, "fsync streamed output after this many findings")
	flag.IntVar(&repoConcurrency, "repo-concurrency", 1, "number of repositories to scan concurrently for GitHub org/enterprise/access scans")
	flag.StringVar(&customPath, "custom-detectors", "", "path to custom detector JSON")
	flag.StringVar(&baselinePath, "baseline", "", "path to baseline JSON of accepted fingerprints")
	flag.StringVar(&writeBaselinePath, "write-baseline", "", "write finding fingerprints to baseline JSON")
	flag.StringVar(&summaryOutputPath, "summary-output", "", "write GitHub discovery and scan summary JSON to this path")
	flag.StringVar(&scanJobID, "scan-job-id", "", "persist per-repository scan state under this job ID for resume/retry")
	flag.StringVar(&scanJobPath, "scan-job-path", "", "path to scan job state JSON; defaults to .secret-sniffer-jobs/<job-id>.json")
	flag.BoolVar(&scanResume, "scan-resume", false, "with --scan-job-id, skip repositories already completed in the job state")
	flag.BoolVar(&scanRetryFailed, "scan-retry-failed", false, "with --scan-job-id, scan only repositories marked failed in the job state")
	flag.StringVar(&githubOrgs, "github-org", "", "comma-separated GitHub organization names to enumerate and scan")
	flag.StringVar(&githubEnterprise, "github-enterprise", "", "GitHub Enterprise Cloud slug; enumerate orgs and scan all repos")
	flag.StringVar(&githubToken, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for API enumeration and private clones; defaults to GITHUB_TOKEN")
	flag.StringVar(&githubAppID, "github-app-id", os.Getenv("GITHUB_APP_ID"), "GitHub App ID for minting installation tokens; defaults to GITHUB_APP_ID")
	flag.StringVar(&githubAppPrivateKey, "github-app-private-key", os.Getenv("GITHUB_APP_PRIVATE_KEY"), "path to GitHub App private key PEM; defaults to GITHUB_APP_PRIVATE_KEY")
	flag.StringVar(&githubInstallationID, "github-installation-id", os.Getenv("GITHUB_INSTALLATION_ID"), "optional GitHub App installation ID; defaults to GITHUB_INSTALLATION_ID")
	flag.BoolVar(&githubAccessible, "github-accessible", false, "scan all repositories accessible to the GitHub token")
	flag.BoolVar(&summaryOnly, "summary-only", false, "discover GitHub orgs/repositories, write summary, and exit without scanning")
	flag.BoolVar(&listDetectors, "list-detectors", false, "print detector metadata as JSON and exit")
	flag.BoolVar(&truffleHogParity, "trufflehog-parity", false, "print tracked TruffleHog detector parity mappings as JSON and exit")
	flag.BoolVar(&failOnFindings, "fail-on-findings", false, "exit with status 2 when findings are present")
	flag.BoolVar(&redact, "redact", false, "omit raw secrets from machine-readable output")
	flag.BoolVar(&noRedact, "no-redact", true, "include raw secrets in machine-readable output; default true")
	flag.BoolVar(&quiet, "quiet", false, "suppress progress logs on stderr")
	flag.BoolVar(&noColor, "no-color", false, "disable colored console output")
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
	if repoConcurrency < 1 {
		repoConcurrency = 1
	}
	cfg.Include = splitCSV(include)
	cfg.Exclude = splitCSV(exclude)
	runtime.GOMAXPROCS(cfg.Workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	console := newConsole(quiet, noColor)
	console.step("Starting scan")
	githubClients, err := githubClients(ctx, githubToken, githubAppID, githubAppPrivateKey, githubInstallationID, githubAccessible, githubOrgs)
	if err != nil {
		fatal(err)
	}
	targets, tokenByTarget, _, installationByTarget, summary, err := scanTargets(ctx, cfg.Target, githubOrgs, githubEnterprise, githubAccessible, githubClients, console)
	if err != nil {
		fatal(err)
	}
	console.discoverySummary(summary)
	jobPath := ""
	var jobState *scanJobState
	if scanResume && scanRetryFailed {
		fatal(fmt.Errorf("--scan-resume and --scan-retry-failed cannot be used together"))
	}
	if !summaryOnly && scanJobID == "" && !scanResume && !scanRetryFailed {
		scanJobID, err = defaultScanJobID(scanJobPrefix(cfg.Target, githubOrgs, githubEnterprise, githubAccessible))
		if err != nil {
			fatal(err)
		}
	}
	if !summaryOnly && (scanJobID != "" || scanJobPath != "" || scanResume || scanRetryFailed) {
		if scanJobID == "" {
			fatal(fmt.Errorf("--scan-job-id is required when using --scan-resume or --scan-retry-failed"))
		}
		jobPath = scanJobStatePath(scanJobID, scanJobPath)
		jobState, err = loadOrCreateScanJobState(jobPath, scanJobID, start)
		if err != nil {
			fatal(err)
		}
		jobState.addTargets(targets)
		if err := writeScanJobState(jobPath, jobState); err != nil {
			fatal(err)
		}
		originalTargets := len(targets)
		targets = filterScanJobTargets(targets, jobState, scanResume, scanRetryFailed)
		summary.TotalRepositories = len(targets)
		console.info("Scan job %s state=%s selected_repos=%d discovered_repos=%d", scanJobID, jobPath, len(targets), originalTargets)
	}
	if summaryOutputPath == "" && isGitHubDiscovery(githubOrgs, githubEnterprise, githubAccessible) {
		summaryOutputPath = "secret-sniffer-summary.json"
	}
	if summaryOutputPath != "" {
		if err := writeSummary(summaryOutputPath, summary); err != nil {
			fatal(err)
		}
		console.info("Wrote discovery summary to %s", summaryOutputPath)
	}
	if summaryOnly {
		console.done(0, time.Since(start).Round(time.Millisecond))
		return
	}
	console.info("Scanning %d target(s), workers=%d, repo_concurrency=%d", len(targets), cfg.Workers, repoConcurrency)
	includeSecrets := noRedact && !redact
	format = strings.ToLower(format)
	if outputPath == "" {
		outputPath = defaultOutputPath(format)
	}
	var outputFile *os.File
	if outputPath != "" {
		outputFlags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if jobState != nil && format == "jsonl" && (scanResume || scanRetryFailed) {
			outputFlags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		outputFile, err = os.OpenFile(outputPath, outputFlags, 0o600)
		if err != nil {
			fatal(err)
		}
		defer outputFile.Close()
		if format == "jsonl" {
			console.info("Streaming findings to %s", outputPath)
		} else {
			console.info("Writing %s output to %s", format, outputPath)
		}
	}
	var knownBaseline map[string]struct{}
	if baselinePath != "" {
		console.info("Loading baseline %s", baselinePath)
		knownBaseline, err = baseline.Load(baselinePath)
		if err != nil {
			fatal(err)
		}
	}
	tokenCache := map[int64]githubapi.InstallationToken{}
	for _, gc := range githubClients {
		if gc.installationID > 0 {
			tokenCache[gc.installationID] = githubapi.InstallationToken{Token: gc.token, ExpiresAt: gc.tokenExpiresAt}
		}
	}
	var findings []detectors.Finding
	totalBeforeBaseline := 0
	totalAfterBaseline := 0
	streamedSinceSync := 0
	var mu sync.Mutex
	var tokenMu sync.Mutex
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < repoConcurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				target := targets[i]
				console.repoStart(i+1, len(targets), target)
				if jobState != nil {
					mu.Lock()
					jobState.markRunning(target, time.Now())
					if err := writeScanJobState(jobPath, jobState); err != nil {
						mu.Unlock()
						fatal(err)
					}
					mu.Unlock()
				}
				targetCfg := cfg
				targetCfg.Target = target
				targetCfg.GitHubToken = tokenByTarget[target]
				if installationID := installationByTarget[target]; installationID > 0 && githubAppID != "" && githubAppPrivateKey != "" {
					token, refreshed, err := cachedInstallationToken(ctx, githubAppID, githubAppPrivateKey, installationID, tokenCache, &tokenMu)
					if err != nil {
						err = fmt.Errorf("get github installation token for %s: %w", target, err)
						if isGitHubCloneTarget(target) {
							console.repoError(i+1, len(targets), target, err)
							mu.Lock()
							summary.addScanFailure(target, err)
							if jobState != nil {
								jobState.markFailed(target, err, time.Now())
								if writeErr := writeScanJobState(jobPath, jobState); writeErr != nil {
									mu.Unlock()
									fatal(writeErr)
								}
							}
							mu.Unlock()
							continue
						}
						fatal(err)
					}
					targetCfg.GitHubToken = token.Token
					if refreshed {
						console.info("[%d/%d] Refreshed GitHub App installation token, expires=%s", i+1, len(targets), token.ExpiresAt.Format(time.RFC3339))
					}
				}
				runner := scanner.New(targetCfg, registry)
				targetFindings, err := runner.Scan(ctx)
				if err != nil {
					if isGitHubCloneTarget(target) {
						console.repoError(i+1, len(targets), target, err)
						mu.Lock()
						summary.addScanFailure(target, err)
						if jobState != nil {
							jobState.markFailed(target, err, time.Now())
							if writeErr := writeScanJobState(jobPath, jobState); writeErr != nil {
								mu.Unlock()
								fatal(writeErr)
							}
						}
						mu.Unlock()
						continue
					}
					fatal(err)
				}
				mu.Lock()
				totalBeforeBaseline += len(targetFindings)
				mu.Unlock()
				if knownBaseline != nil {
					targetFindings = baseline.Filter(targetFindings, knownBaseline)
				}
				mu.Lock()
				totalAfterBaseline += len(targetFindings)
				mu.Unlock()
				console.repoDone(i+1, len(targets), target, len(targetFindings))
				mu.Lock()
				summary.addScanResult(target, len(targetFindings))
				if jobState != nil {
					jobState.markCompleted(target, len(targetFindings), time.Now())
					if err := writeScanJobState(jobPath, jobState); err != nil {
						mu.Unlock()
						fatal(err)
					}
				}
				mu.Unlock()
				for _, finding := range targetFindings {
					console.finding(finding)
					if outputFile != nil && format == "jsonl" {
						mu.Lock()
						if err := output.WriteFindingJSONL(outputFile, finding, includeSecrets); err != nil {
							mu.Unlock()
							fatal(err)
						}
						streamedSinceSync++
						if outputFlushFindings < 1 || streamedSinceSync >= outputFlushFindings {
							if err := outputFile.Sync(); err != nil {
								mu.Unlock()
								fatal(err)
							}
							streamedSinceSync = 0
						}
						mu.Unlock()
					}
				}
				mu.Lock()
				if outputFile != nil && format == "jsonl" && streamedSinceSync > 0 {
					if err := outputFile.Sync(); err != nil {
						mu.Unlock()
						fatal(err)
					}
					streamedSinceSync = 0
				}
				if outputFile == nil || format != "jsonl" || writeBaselinePath != "" {
					findings = append(findings, targetFindings...)
				}
				mu.Unlock()
			}
		}()
	}
	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if writeBaselinePath != "" {
		if err := baseline.Write(writeBaselinePath, findings); err != nil {
			fatal(err)
		}
	}
	summary.FindingsBeforeBaseline = totalBeforeBaseline
	summary.FindingsAfterBaseline = totalAfterBaseline
	console.scanSummary(summary)
	if summaryOutputPath != "" {
		if err := writeSummary(summaryOutputPath, summary); err != nil {
			fatal(err)
		}
		console.info("Updated summary at %s", summaryOutputPath)
	}

	meta := output.Meta{Target: strings.Join(targets, ","), StartedAt: start, Duration: time.Since(start), Findings: totalAfterBaseline}
	if outputFile == nil {
		if err := output.Write(os.Stdout, format, findings, meta, includeSecrets); err != nil {
			fatal(err)
		}
	} else if format != "jsonl" {
		if err := output.Write(outputFile, format, findings, meta, includeSecrets); err != nil {
			fatal(err)
		}
		if err := outputFile.Sync(); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stdout, "scan complete: %d findings in %s, output=%s\n", summary.FindingsAfterBaseline, time.Since(start).Round(time.Millisecond), outputPath)
	} else {
		fmt.Fprintf(os.Stdout, "scan complete: %d findings in %s, output=%s\n", summary.FindingsAfterBaseline, time.Since(start).Round(time.Millisecond), outputPath)
	}
	console.done(totalAfterBaseline, time.Since(start).Round(time.Millisecond))
	if failOnFindings && totalAfterBaseline > 0 {
		os.Exit(2)
	}
}

type githubClient struct {
	client         *githubapi.Client
	token          string
	tokenExpiresAt time.Time
	installationID int64
	account        string
	accountType    string
}

type discoverySummary struct {
	Enterprise             string                `json:"enterprise,omitempty"`
	RequestedOrgs          []string              `json:"requested_orgs,omitempty"`
	Accessible             bool                  `json:"accessible"`
	TotalRepositories      int                   `json:"total_repositories"`
	FailedScans            int                   `json:"failed_scans,omitempty"`
	ScanFailures           []scanFailureSummary  `json:"scan_failures,omitempty"`
	FindingsBeforeBaseline int                   `json:"findings_before_baseline"`
	FindingsAfterBaseline  int                   `json:"findings_after_baseline"`
	Installations          []installationSummary `json:"installations,omitempty"`
	Orgs                   []orgSummary          `json:"orgs"`
}

type scanFailureSummary struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

type installationSummary struct {
	ID           int64  `json:"id"`
	Account      string `json:"account"`
	AccountType  string `json:"account_type"`
	Repositories int    `json:"repositories"`
}

type orgSummary struct {
	Name         string `json:"name"`
	Repositories int    `json:"repositories"`
	Findings     int    `json:"findings"`
}

type scanJobState struct {
	JobID     string                   `json:"job_id"`
	CreatedAt time.Time                `json:"created_at"`
	UpdatedAt time.Time                `json:"updated_at"`
	Targets   map[string]scanJobTarget `json:"targets"`
}

type scanJobTarget struct {
	Status      string    `json:"status"`
	Findings    int       `json:"findings,omitempty"`
	Attempts    int       `json:"attempts,omitempty"`
	Error       string    `json:"error,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

const (
	scanJobPending   = "pending"
	scanJobRunning   = "running"
	scanJobCompleted = "completed"
	scanJobFailed    = "failed"
)

func githubClients(ctx context.Context, token, appID, privateKeyPath, installationIDRaw string, allInstallations bool, orgsRaw string) ([]githubClient, error) {
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
			out = append(out, githubClient{client: githubapi.New(token.Token), token: token.Token, tokenExpiresAt: token.ExpiresAt, installationID: installation.ID, account: installation.Account.Login, accountType: installation.Account.Type})
		}
		return out, nil
	}
	var installationID int64
	var account string
	var accountType string
	if installationIDRaw == "" {
		orgs := splitCSV(orgsRaw)
		if len(orgs) > 0 {
			jwt, err := githubapi.CreateAppJWT(appID, privateKeyPath, time.Now())
			if err != nil {
				return nil, err
			}
			appClient := githubapi.New(jwt)
			out := make([]githubClient, 0, len(orgs))
			for _, org := range orgs {
				installation, err := appClient.InstallationForOrg(ctx, org)
				if err != nil {
					return nil, fmt.Errorf("get github app installation for org %s: %w", org, err)
				}
				installationToken, err := appClient.InstallationToken(ctx, installation.ID)
				if err != nil {
					return nil, fmt.Errorf("mint installation token for %s/%d: %w", installation.Account.Login, installation.ID, err)
				}
				out = append(out, githubClient{client: githubapi.New(installationToken.Token), token: installationToken.Token, tokenExpiresAt: installationToken.ExpiresAt, installationID: installation.ID, account: installation.Account.Login, accountType: installation.Account.Type})
			}
			return out, nil
		}
	}
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
		account = installations[0].Account.Login
		accountType = installations[0].Account.Type
	}
	installationToken, err := refreshInstallationToken(ctx, appID, privateKeyPath, installationID)
	if err != nil {
		return nil, err
	}
	return []githubClient{{client: githubapi.New(installationToken.Token), token: installationToken.Token, tokenExpiresAt: installationToken.ExpiresAt, installationID: installationID, account: account, accountType: accountType}}, nil
}

func scanTargets(ctx context.Context, target, orgs, enterprise string, accessible bool, clients []githubClient, console console) ([]string, map[string]string, map[string]time.Time, map[string]int64, discoverySummary, error) {
	var targets []string
	tokens := map[string]string{}
	expires := map[string]time.Time{}
	installations := map[string]int64{}
	summary := discoverySummary{Enterprise: enterprise, RequestedOrgs: splitCSV(orgs), Accessible: accessible, Orgs: []orgSummary{}}
	for _, org := range splitCSV(orgs) {
		console.info("Discovering repositories for GitHub org %s", org)
		for _, gc := range clients {
			if gc.account != "" && !strings.EqualFold(gc.account, org) {
				continue
			}
			repos, err := gc.client.RepositoriesForOrg(ctx, org)
			if err != nil {
				return nil, nil, nil, nil, summary, err
			}
			console.info("Discovered %d repositories for org %s", len(repos), org)
			addRepos(&targets, tokens, expires, installations, repos, gc)
			summary.addRepos(repos)
			summary.addInstallation(gc, len(repos))
		}
	}
	if enterprise != "" {
		console.info("Discovering repositories for GitHub enterprise %s", enterprise)
		for _, gc := range clients {
			repos, err := gc.client.RepositoriesForEnterprise(ctx, enterprise)
			if err != nil {
				return nil, nil, nil, nil, summary, err
			}
			console.info("Discovered %d repositories for enterprise %s", len(repos), enterprise)
			addRepos(&targets, tokens, expires, installations, repos, gc)
			summary.addRepos(repos)
			summary.addInstallation(gc, len(repos))
		}
	}
	if accessible {
		console.info("Discovering all repositories accessible to GitHub credential(s)")
		for _, gc := range clients {
			repos, err := gc.client.AccessibleRepositories(ctx)
			if err != nil {
				return nil, nil, nil, nil, summary, err
			}
			if gc.account != "" {
				console.info("Discovered %d accessible repositories for installation %d (%s)", len(repos), gc.installationID, gc.account)
			} else {
				console.info("Discovered %d accessible repositories", len(repos))
			}
			addRepos(&targets, tokens, expires, installations, repos, gc)
			summary.addRepos(repos)
			summary.addInstallation(gc, len(repos))
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
	summary.sortInstallations()
	return targets, tokens, expires, installations, summary, nil
}

type console struct {
	quiet bool
	color bool
}

const (
	colorReset  = "\033[0m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func newConsole(quiet, noColor bool) console {
	return console{quiet: quiet, color: !noColor}
}

func (c console) printf(label, color, format string, args ...any) {
	if c.quiet {
		return
	}
	if c.color {
		fmt.Fprintf(os.Stderr, "%s%-9s%s %s\n", color, label, colorReset, fmt.Sprintf(format, args...))
		return
	}
	fmt.Fprintf(os.Stderr, "%-9s %s\n", label, fmt.Sprintf(format, args...))
}

func (c console) step(msg string, args ...any) { c.printf("START", colorBlue, msg, args...) }
func (c console) info(msg string, args ...any) { c.printf("INFO", colorCyan, msg, args...) }
func (c console) done(findings int, duration time.Duration) {
	c.printf("DONE", colorGreen, "findings=%d duration=%s", findings, duration)
}

func (c console) repoStart(current, total int, target string) {
	c.printf("REPO", colorBlue, "[%d/%d] %s", current, total, target)
}

func (c console) repoDone(current, total int, target string, findings int) {
	clr := colorGreen
	if findings > 0 {
		clr = colorYellow
	}
	c.printf("REPO", clr, "[%d/%d] done findings=%d %s", current, total, findings, target)
}

func (c console) repoError(current, total int, target string, err error) {
	c.printf("WARN", colorYellow, "[%d/%d] skipped %s: %v", current, total, target, err)
}

func (c console) finding(f detectors.Finding) {
	if c.quiet {
		return
	}
	clr := severityColor(f.Severity)
	secret := f.Secret
	if secret == "" {
		secret = f.Redacted
	}
	verified := ""
	if f.Verified {
		verified = " verified"
	}
	if c.color {
		fmt.Fprintf(os.Stderr, "%s%-9s%s %s%s%s %s:%d:%d %s%s%s %s\n", clr, "FINDING", colorReset, colorBold, strings.ToUpper(f.Severity), colorReset, f.File, f.Line, f.Column, colorDim, f.Name+verified, colorReset, secret)
		return
	}
	fmt.Fprintf(os.Stderr, "%-9s %s %s:%d:%d %s%s %s\n", "FINDING", strings.ToUpper(f.Severity), f.File, f.Line, f.Column, f.Name, verified, secret)
}

func (c console) discoverySummary(summary discoverySummary) {
	if c.quiet || summary.TotalRepositories == 0 {
		return
	}
	if summary.Enterprise != "" {
		c.info("GitHub enterprise: %s", summary.Enterprise)
	} else if summary.Accessible {
		c.info("Accessible repository discovery")
	} else if len(summary.RequestedOrgs) > 0 {
		c.info("Organization discovery")
	} else {
		c.info("Target discovery")
	}
	if len(summary.RequestedOrgs) > 0 {
		c.info("Requested orgs: %s", strings.Join(summary.RequestedOrgs, ", "))
	}
	if len(summary.Installations) > 0 {
		c.info("GitHub App installations=%d", len(summary.Installations))
		for _, installation := range summary.Installations {
			account := installation.Account
			if account == "" {
				account = "unknown"
			}
			c.printf("INSTALL", colorCyan, "%s id=%d type=%s repos=%d", account, installation.ID, installation.AccountType, installation.Repositories)
		}
	}
	c.info("Discovered orgs=%d repos=%d", len(summary.Orgs), summary.TotalRepositories)
	for _, org := range summary.Orgs {
		c.printf("ORG", colorCyan, "%s repos=%d", org.Name, org.Repositories)
	}
}

func (c console) scanSummary(summary discoverySummary) {
	if c.quiet || summary.TotalRepositories == 0 {
		return
	}
	c.printf("SUMMARY", colorBold, "repos=%d failed=%d findings_before_baseline=%d findings_after_baseline=%d", summary.TotalRepositories, summary.FailedScans, summary.FindingsBeforeBaseline, summary.FindingsAfterBaseline)
	for _, org := range summary.Orgs {
		c.printf("ORG", colorCyan, "%s repos=%d findings=%d", org.Name, org.Repositories, org.Findings)
	}
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return colorRed
	case "medium":
		return colorYellow
	case "low":
		return colorBlue
	default:
		return colorCyan
	}
}

func defaultOutputPath(format string) string {
	switch format {
	case "json":
		return "secret-sniffer-findings.json"
	case "jsonl":
		return "secret-sniffer-findings.jsonl"
	case "sarif":
		return "secret-sniffer-findings.sarif"
	default:
		return ""
	}
}

func isGitHubDiscovery(orgs, enterprise string, accessible bool) bool {
	return orgs != "" || enterprise != "" || accessible
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

func cachedInstallationToken(ctx context.Context, appID, privateKeyPath string, installationID int64, cache map[int64]githubapi.InstallationToken, mu *sync.Mutex) (githubapi.InstallationToken, bool, error) {
	mu.Lock()
	defer mu.Unlock()
	if token, ok := cache[installationID]; ok && !shouldRefreshToken(token.ExpiresAt, time.Now()) {
		return token, false, nil
	}
	token, err := refreshInstallationToken(ctx, appID, privateKeyPath, installationID)
	if err != nil {
		return githubapi.InstallationToken{}, false, err
	}
	cache[installationID] = token
	return token, true, nil
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

func (s *discoverySummary) addInstallation(gc githubClient, repos int) {
	if gc.installationID == 0 {
		return
	}
	for i := range s.Installations {
		if s.Installations[i].ID == gc.installationID {
			s.Installations[i].Repositories += repos
			return
		}
	}
	s.Installations = append(s.Installations, installationSummary{ID: gc.installationID, Account: gc.account, AccountType: gc.accountType, Repositories: repos})
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

func (s *discoverySummary) addScanFailure(target string, err error) {
	s.FailedScans++
	s.ScanFailures = append(s.ScanFailures, scanFailureSummary{Target: target, Error: err.Error()})
}

func (s *discoverySummary) sortOrgs() {
	slices.SortFunc(s.Orgs, func(a, b orgSummary) int { return strings.Compare(a.Name, b.Name) })
}

func (s *discoverySummary) sortInstallations() {
	slices.SortFunc(s.Installations, func(a, b installationSummary) int {
		if a.Account == b.Account {
			return cmp.Compare(a.ID, b.ID)
		}
		return strings.Compare(a.Account, b.Account)
	})
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
	if err == nil {
		host := strings.ToLower(u.Host)
		if host != "github.com" && host != "www.github.com" {
			return ""
		}
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

func isGitHubCloneTarget(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Host)
	return (u.Scheme == "http" || u.Scheme == "https") && (host == "github.com" || host == "www.github.com")
}

func scanJobStatePath(jobID, explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	return filepath.Join(".secret-sniffer-jobs", jobID+".json")
}

func defaultScanJobID(prefix string) (string, error) {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%08d", prefix, n.Int64()), nil
}

func scanJobPrefix(target, orgs, enterprise string, accessible bool) string {
	switch {
	case enterprise != "":
		return sanitizeScanJobPrefix("enterprise-" + enterprise)
	case orgs != "":
		return sanitizeScanJobPrefix("org-" + strings.Join(splitCSV(orgs), "-"))
	case accessible:
		return "accessible"
	case isGitHubCloneTarget(target):
		return sanitizeScanJobPrefix("repo-" + strings.TrimSuffix(strings.Trim(strings.TrimPrefix(githubPath(target), "/"), "/"), ".git"))
	default:
		name := filepath.Base(target)
		if name == "." || name == string(filepath.Separator) {
			if wd, err := os.Getwd(); err == nil {
				name = filepath.Base(wd)
			}
		}
		return sanitizeScanJobPrefix("target-" + name)
	}
}

func githubPath(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	return u.Path
}

func sanitizeScanJobPrefix(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "scan"
	}
	if len(out) > 60 {
		out = strings.Trim(out[:60], "-")
		if out == "" {
			return "scan"
		}
	}
	return out
}

func loadOrCreateScanJobState(path, jobID string, now time.Time) (*scanJobState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &scanJobState{JobID: jobID, CreatedAt: now, UpdatedAt: now, Targets: map[string]scanJobTarget{}}, nil
		}
		return nil, err
	}
	var state scanJobState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, fmt.Errorf("read scan job state %s: %w", path, err)
	}
	if state.JobID != jobID {
		return nil, fmt.Errorf("scan job state %s has job_id %q, want %q", path, state.JobID, jobID)
	}
	if state.Targets == nil {
		state.Targets = map[string]scanJobTarget{}
	}
	return &state, nil
}

func writeScanJobState(path string, state *scanJobState) error {
	state.UpdatedAt = time.Now()
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".scan-job-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *scanJobState) addTargets(targets []string) {
	if s.Targets == nil {
		s.Targets = map[string]scanJobTarget{}
	}
	for _, target := range targets {
		if _, ok := s.Targets[target]; ok {
			continue
		}
		s.Targets[target] = scanJobTarget{Status: scanJobPending}
	}
}

func (s *scanJobState) markRunning(target string, now time.Time) {
	entry := s.Targets[target]
	entry.Status = scanJobRunning
	entry.Attempts++
	entry.Findings = 0
	entry.Error = ""
	entry.StartedAt = now
	entry.CompletedAt = time.Time{}
	s.Targets[target] = entry
}

func (s *scanJobState) markCompleted(target string, findings int, now time.Time) {
	entry := s.Targets[target]
	entry.Status = scanJobCompleted
	entry.Findings = findings
	entry.Error = ""
	entry.CompletedAt = now
	s.Targets[target] = entry
}

func (s *scanJobState) markFailed(target string, err error, now time.Time) {
	entry := s.Targets[target]
	entry.Status = scanJobFailed
	entry.Findings = 0
	entry.Error = err.Error()
	entry.CompletedAt = now
	s.Targets[target] = entry
}

func filterScanJobTargets(targets []string, state *scanJobState, resume, retryFailed bool) []string {
	if state == nil || (!resume && !retryFailed) {
		return targets
	}
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		entry := state.Targets[target]
		switch {
		case retryFailed:
			if entry.Status == scanJobFailed {
				out = append(out, target)
			}
		case resume:
			if entry.Status != scanJobCompleted {
				out = append(out, target)
			}
		}
	}
	return out
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
