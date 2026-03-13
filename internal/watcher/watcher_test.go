package watcher

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcherDebounce(t *testing.T) {
	tmpDir := t.TempDir()
	
	var callCount int32
	onChange := func() {
		atomic.AddInt32(&callCount, 1)
	}

	w, err := New(tmpDir, onChange)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer w.Close()

	// Wait for watcher to start listening
	time.Sleep(100 * time.Millisecond)

	// Trigger multiple events
	testFile := filepath.Join(tmpDir, "cas", "test.pem")
	for i := 0; i < 5; i++ {
		os.WriteFile(testFile, []byte("data"), 0644)
		time.Sleep(100 * time.Millisecond)
	}

	// Verify that it hasn't been called yet (due to debounce)
	if atomic.LoadInt32(&callCount) > 0 {
		t.Errorf("onChange called too early, expected debounce")
	}

	// Wait for debounce (2s + buffer)
	time.Sleep(3 * time.Second)

	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected onChange to be called exactly once, got %d", callCount)
	}
}

func TestWatcherSubdirs(t *testing.T) {
	tmpDir := t.TempDir()
	// Test that it creates subdirs if they don't exist
	_, err := New(tmpDir, func() {})
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	for _, sub := range []string{"cas", "crls", "responders"} {
		p := filepath.Join(tmpDir, sub)
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			t.Errorf("expected directory %s to exist, err: %v", p, err)
		}
	}
}
