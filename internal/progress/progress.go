package progress

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = 1

const (
	PhaseInitializing     = "initializing"
	PhaseDiscovering      = "discovering"
	PhaseListing          = "listing"
	PhaseCloning          = "cloning"
	PhaseScanningWorktree = "scanning_worktree"
	PhaseScanningHistory  = "scanning_history"
	PhaseDownloading      = "downloading"
	PhaseExtracting       = "extracting"
	PhaseScanning         = "scanning"
	PhaseFinalizing       = "finalizing"
	PhaseCompleted        = "completed"
	PhaseFailed           = "failed"
	PhaseCancelled        = "cancelled"
)

const (
	StageQueued      = "queued"
	StageDownloading = "downloading"
	StageDownloaded  = "downloaded"
	StageExtracting  = "extracting"
	StageScanning    = "scanning"
	StageCompleted   = "completed"
	StageSkipped     = "skipped"
	StageFailed      = "failed"
)

type Counters struct {
	ItemsDiscovered int64 `json:"items_discovered"`
	ItemsQueued     int64 `json:"items_queued"`
	ItemsActive     int64 `json:"items_active"`
	ItemsCompleted  int64 `json:"items_completed"`
	ItemsSkipped    int64 `json:"items_skipped"`
	ItemsFailed     int64 `json:"items_failed"`
	BytesDownloaded int64 `json:"bytes_downloaded"`
	Findings        int64 `json:"findings"`
}

type Item struct {
	Slot         string    `json:"slot"`
	Stage        string    `json:"stage"`
	Bucket       string    `json:"bucket,omitempty"`
	Path         string    `json:"path"`
	ArchiveEntry string    `json:"archive_entry,omitempty"`
	ArchiveDepth int       `json:"archive_depth,omitempty"`
	Commit       string    `json:"commit,omitempty"`
	BytesRead    int64     `json:"bytes_read,omitempty"`
	BytesTotal   int64     `json:"bytes_total,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	Reason       string    `json:"reason,omitempty"`
	Error        string    `json:"error,omitempty"`
	CountBytes   bool      `json:"-"`
}

type ItemUpdate struct {
	Stage               string
	ArchiveEntry        string
	ArchiveDepth        int
	ClearArchive        bool
	ResetBytes          bool
	DisableByteCounting bool
	BytesRead           int64
	BytesTotal          int64
}

type ItemResult struct {
	Stage     string
	Reason    string
	Error     string
	BytesRead int64
	Findings  int64
}

type CompletedItem struct {
	Stage        string `json:"stage"`
	Bucket       string `json:"bucket,omitempty"`
	Path         string `json:"path"`
	ArchiveEntry string `json:"archive_entry,omitempty"`
	ArchiveDepth int    `json:"archive_depth,omitempty"`
	Commit       string `json:"commit,omitempty"`
	BytesRead    int64  `json:"bytes_read,omitempty"`
	Findings     int64  `json:"findings,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
	Reason       string `json:"reason,omitempty"`
	Error        string `json:"error,omitempty"`
}

type State struct {
	SchemaVersion int            `json:"schema_version"`
	Sequence      int64          `json:"sequence"`
	UpdatedAt     time.Time      `json:"updated_at"`
	SourceType    string         `json:"source_type"`
	Target        string         `json:"target"`
	Phase         string         `json:"phase"`
	Counters      Counters       `json:"counters"`
	ActiveItems   []Item         `json:"active_items"`
	LastCompleted *CompletedItem `json:"last_completed,omitempty"`
	Error         string         `json:"error,omitempty"`
}

type Final struct {
	Phase string
	Error string
}

type ProgressReporter interface {
	SetPhase(phase string)
	SetDiscovered(count int64)
	DiscoverItems(count int64)
	QueueItems(count int64)
	SkipItems(count int64)
	AddFindings(count int64)
	StartItem(slot string, item Item)
	UpdateItem(slot string, update ItemUpdate)
	CompleteItem(slot string, result ItemResult)
	Snapshot()
	Close(final Final)
}

type Reporter struct {
	mu          sync.Mutex
	path        string
	interval    time.Duration
	warn        func(error)
	state       State
	active      map[string]Item
	generation  uint64
	dirty       bool
	notify      chan struct{}
	final       chan Final
	done        chan struct{}
	closeOnce   sync.Once
	writeFile   func(string, State) error
	resumePhase string
	closing     bool
}

func New(path string, interval time.Duration, sourceType, target string, warn func(error)) (*Reporter, error) {
	if interval <= 0 {
		return nil, errors.New("progress interval must be greater than zero")
	}
	r := &Reporter{
		path: path, interval: interval, warn: warn, active: map[string]Item{},
		notify: make(chan struct{}, 1), final: make(chan Final, 1), done: make(chan struct{}), writeFile: writeState,
		state: State{SchemaVersion: SchemaVersion, SourceType: sourceType, Target: sanitizeLocation(target), Phase: PhaseInitializing},
	}
	r.generation = 1
	r.dirty = true
	if err := r.publish(true); err != nil {
		return nil, err
	}
	go r.run()
	return r, nil
}

func (r *Reporter) SetPhase(phase string) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	if r.state.Phase == PhaseExtracting {
		r.resumePhase = phase
		r.mu.Unlock()
		return
	}
	if r.state.Phase == phase {
		r.mu.Unlock()
		return
	}
	r.state.Phase = phase
	r.changedLocked()
	r.mu.Unlock()
	r.signal()
}

func (r *Reporter) SetDiscovered(count int64) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	if count > r.state.Counters.ItemsDiscovered {
		r.state.Counters.ItemsDiscovered = count
		r.changedLocked()
	}
	r.mu.Unlock()
}

func (r *Reporter) DiscoverItems(count int64) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.state.Counters.ItemsDiscovered += count
	r.changedLocked()
	r.mu.Unlock()
}

func (r *Reporter) QueueItems(count int64) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.state.Counters.ItemsQueued += count
	if r.state.Counters.ItemsQueued < 0 {
		r.state.Counters.ItemsQueued = 0
	}
	r.changedLocked()
	r.mu.Unlock()
}

func (r *Reporter) SkipItems(count int64) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.state.Counters.ItemsSkipped += count
	r.changedLocked()
	r.mu.Unlock()
}

func (r *Reporter) AddFindings(count int64) {
	if count <= 0 {
		return
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.state.Counters.Findings += count
	r.changedLocked()
	r.mu.Unlock()
}

func (r *Reporter) StartItem(slot string, item Item) {
	if slot == "" {
		return
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	if r.state.Counters.ItemsQueued > 0 {
		r.state.Counters.ItemsQueued--
	}
	item.Slot = slot
	if item.StartedAt.IsZero() {
		item.StartedAt = time.Now().UTC()
	}
	item.Bucket = sanitizeLocation(item.Bucket)
	item.Path = sanitizeLocation(item.Path)
	item.ArchiveEntry = sanitizeLocation(item.ArchiveEntry)
	item.Error = sanitize(item.Error)
	r.active[slot] = item
	r.changedLocked()
	r.mu.Unlock()
}

func (r *Reporter) UpdateItem(slot string, update ItemUpdate) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	item, ok := r.active[slot]
	if !ok {
		r.mu.Unlock()
		return
	}
	oldStage := item.Stage
	if update.Stage != "" {
		item.Stage = update.Stage
	}
	if update.ClearArchive {
		item.ArchiveEntry = ""
		item.ArchiveDepth = 0
	} else if update.ArchiveEntry != "" {
		item.ArchiveEntry = sanitizeLocation(update.ArchiveEntry)
		item.ArchiveDepth = update.ArchiveDepth
	}
	if update.DisableByteCounting {
		item.CountBytes = false
	}
	if update.ResetBytes {
		item.BytesRead = 0
		item.BytesTotal = update.BytesTotal
	} else if update.BytesTotal > 0 {
		item.BytesTotal = update.BytesTotal
	}
	if update.BytesRead > item.BytesRead {
		if item.CountBytes {
			r.state.Counters.BytesDownloaded += update.BytesRead - item.BytesRead
		}
		item.BytesRead = update.BytesRead
	}
	r.active[slot] = item
	phaseChanged := r.updateExtractingPhaseLocked(oldStage, item.Stage)
	r.changedLocked()
	r.mu.Unlock()
	if phaseChanged {
		r.signal()
	}
}

func (r *Reporter) CompleteItem(slot string, result ItemResult) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	item, ok := r.active[slot]
	if !ok {
		r.mu.Unlock()
		return
	}
	if result.BytesRead > item.BytesRead {
		if item.CountBytes {
			r.state.Counters.BytesDownloaded += result.BytesRead - item.BytesRead
		}
		item.BytesRead = result.BytesRead
	}
	stage := result.Stage
	if stage == "" {
		stage = StageCompleted
	}
	switch stage {
	case StageCompleted:
		r.state.Counters.ItemsCompleted++
	case StageSkipped:
		r.state.Counters.ItemsSkipped++
	case StageFailed:
		r.state.Counters.ItemsFailed++
	}
	if result.Findings > 0 {
		r.state.Counters.Findings += result.Findings
	}
	r.state.LastCompleted = &CompletedItem{
		Stage: stage, Bucket: item.Bucket, Path: item.Path, ArchiveEntry: item.ArchiveEntry,
		ArchiveDepth: item.ArchiveDepth, Commit: item.Commit, BytesRead: item.BytesRead,
		Findings: result.Findings, DurationMS: time.Since(item.StartedAt).Milliseconds(),
		Reason: sanitize(result.Reason), Error: sanitize(result.Error),
	}
	delete(r.active, slot)
	phaseChanged := r.updateExtractingPhaseLocked(item.Stage, "")
	r.changedLocked()
	r.mu.Unlock()
	if phaseChanged {
		r.signal()
	}
}

func (r *Reporter) updateExtractingPhaseLocked(oldStage, newStage string) bool {
	if newStage == StageExtracting && oldStage != StageExtracting {
		if r.state.Phase != PhaseExtracting {
			r.resumePhase = r.state.Phase
			r.state.Phase = PhaseExtracting
			return true
		}
		return false
	}
	if oldStage != StageExtracting || newStage == StageExtracting || r.state.Phase != PhaseExtracting {
		return false
	}
	for _, item := range r.active {
		if item.Stage == StageExtracting {
			return false
		}
	}
	r.state.Phase = r.resumePhase
	if r.state.Phase == "" {
		r.state.Phase = PhaseScanning
	}
	r.resumePhase = ""
	return true
}

func (r *Reporter) Snapshot() { r.signal() }

func (r *Reporter) Close(final Final) {
	r.closeOnce.Do(func() {
		r.final <- final
		<-r.done
	})
}

func (r *Reporter) run() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	defer close(r.done)
	for {
		select {
		case <-ticker.C:
			r.publish(false)
		case <-r.notify:
			r.publish(false)
		case final := <-r.final:
			r.mu.Lock()
			r.closing = true
			r.state.Phase = final.Phase
			r.state.Error = sanitize(final.Error)
			r.changedLocked()
			r.mu.Unlock()
			for attempt := 0; attempt < 3; attempt++ {
				if r.publish(true) == nil {
					break
				}
				if attempt < 2 {
					time.Sleep(50 * time.Millisecond)
				}
			}
			return
		}
	}
}

func (r *Reporter) publish(force bool) error {
	r.mu.Lock()
	if !r.dirty && !force {
		r.mu.Unlock()
		return nil
	}
	generation := r.generation
	state := r.snapshotLocked()
	state.Sequence++
	state.UpdatedAt = time.Now().UTC()
	r.mu.Unlock()

	err := r.writeFile(r.path, state)
	r.mu.Lock()
	r.state.Sequence = state.Sequence
	r.state.UpdatedAt = state.UpdatedAt
	if err == nil {
		if r.generation == generation {
			r.dirty = false
		}
	}
	r.mu.Unlock()
	if err != nil && r.warn != nil {
		r.warn(err)
	}
	return err
}

func (r *Reporter) snapshotLocked() State {
	state := r.state
	state.ActiveItems = make([]Item, 0, len(r.active))
	for _, item := range r.active {
		state.ActiveItems = append(state.ActiveItems, item)
	}
	slices.SortFunc(state.ActiveItems, func(a, b Item) int { return strings.Compare(a.Slot, b.Slot) })
	state.Counters.ItemsActive = int64(len(state.ActiveItems))
	return state
}

func (r *Reporter) changedLocked() {
	r.generation++
	r.dirty = true
}

func (r *Reporter) signal() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

func writeState(path string, state State) error {
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".progress-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	remove := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		remove()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		remove()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		remove()
		return err
	}
	if err := tmp.Close(); err != nil {
		remove()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		remove()
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

var sensitiveValue = regexp.MustCompile(`(?i)(["']?(?:authorization|credential|token|secret|signature|x-amz-security-token)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\r\n,}]+)`)
var httpURL = regexp.MustCompile(`https?://[^\s]+`)

func sanitize(message string) string {
	message = sensitiveValue.ReplaceAllString(message, "$1[REDACTED]")
	message = httpURL.ReplaceAllStringFunc(message, func(raw string) string {
		u, err := url.Parse(strings.TrimRight(raw, ".,;"))
		if err != nil {
			return "[REDACTED_URL]"
		}
		u.RawQuery, u.Fragment, u.User = "", "", nil
		return u.String()
	})
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func sanitizeLocation(location string) string {
	return httpURL.ReplaceAllStringFunc(location, func(raw string) string {
		suffix := raw[len(strings.TrimRight(raw, ".,;")):]
		u, err := url.Parse(strings.TrimRight(raw, ".,;"))
		if err != nil {
			return "[REDACTED_URL]" + suffix
		}
		u.RawQuery, u.Fragment, u.User = "", "", nil
		return u.String() + suffix
	})
}

type slotKey struct{}

func WithSlot(ctx context.Context, slot string) context.Context {
	return context.WithValue(ctx, slotKey{}, slot)
}

func Slot(ctx context.Context) string {
	slot, _ := ctx.Value(slotKey{}).(string)
	return slot
}
