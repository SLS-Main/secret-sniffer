package s3scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const StateVersion = 1

const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

type State struct {
	Version   int                    `json:"version"`
	JobID     string                 `json:"job_id"`
	ScopeHash string                 `json:"scope_hash"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	Buckets   map[string]BucketState `json:"buckets"`
}

type BucketState struct {
	Status            string    `json:"status"`
	ContinuationToken string    `json:"continuation_token,omitempty"`
	ObjectsScanned    int64     `json:"objects_scanned"`
	ObjectsSkipped    int64     `json:"objects_skipped"`
	Findings          int64     `json:"findings"`
	Attempts          int       `json:"attempts"`
	Error             string    `json:"error,omitempty"`
	StartedAt         time.Time `json:"started_at,omitempty"`
	CompletedAt       time.Time `json:"completed_at,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

type JobLock struct {
	file *os.File
}

func LockStore(path string) (*JobLock, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("S3 scan job is already running (lock %s): %w", lockPath, err)
	}
	return &JobLock{file: file}, nil
}

func (l *JobLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func OpenStore(path, jobID, scopeHash string, buckets []string, now time.Time) (*Store, error) {
	state := State{Version: StateVersion, JobID: jobID, ScopeHash: scopeHash, CreatedAt: now, UpdatedAt: now, Buckets: map[string]BucketState{}}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &state); err != nil {
			return nil, fmt.Errorf("read S3 scan state %s: %w", path, err)
		}
		if state.Version != StateVersion || state.JobID != jobID || state.ScopeHash != scopeHash {
			return nil, fmt.Errorf("S3 scan state %s does not match this job and scan configuration", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if state.Buckets == nil {
		state.Buckets = map[string]BucketState{}
	}
	for _, bucket := range buckets {
		if _, ok := state.Buckets[bucket]; !ok {
			state.Buckets[bucket] = BucketState{Status: StatusPending}
		}
	}
	store := &Store{path: path, state: state}
	if err := store.writeLocked(now); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.state)
	var snapshot State
	_ = json.Unmarshal(b, &snapshot)
	return snapshot
}

func (s *Store) Bucket(name string) BucketState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Buckets[name]
}

func (s *Store) Start(name string, resume bool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Buckets[name]
	if !resume {
		state = BucketState{}
	}
	state.Status, state.Error, state.CompletedAt = StatusRunning, "", time.Time{}
	state.Attempts++
	state.StartedAt = now
	s.state.Buckets[name] = state
	return s.writeLocked(now)
}

func (s *Store) Checkpoint(name, token string, scanned, skipped, findings int64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Buckets[name]
	state.Status, state.ContinuationToken = StatusRunning, token
	state.ObjectsScanned += scanned
	state.ObjectsSkipped += skipped
	state.Findings += findings
	s.state.Buckets[name] = state
	return s.writeLocked(now)
}

func (s *Store) Complete(name string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Buckets[name]
	state.Status, state.ContinuationToken, state.Error = StatusCompleted, "", ""
	state.CompletedAt = now
	s.state.Buckets[name] = state
	return s.writeLocked(now)
}

func (s *Store) Fail(name string, scanErr error, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Buckets[name]
	state.Status, state.Error, state.CompletedAt = StatusFailed, scanErr.Error(), now
	s.state.Buckets[name] = state
	return s.writeLocked(now)
}

func (s *Store) writeLocked(now time.Time) error {
	s.state.UpdatedAt = now
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".s3-scan-*.tmp")
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
	if err := os.Rename(tmpName, s.path); err != nil {
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
