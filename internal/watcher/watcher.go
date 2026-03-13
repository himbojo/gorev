package watcher

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	fw       *fsnotify.Watcher
	onChange func()
}

func New(dir string, onChange func()) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	for _, sub := range []string{"cas", "crls", "responders"} {
		p := filepath.Join(dir, sub)
		// Ensure the directory exists so the watcher doesn't fail
		if err := os.MkdirAll(p, 0755); err != nil {
			log.Printf("Failed to create watch directory %s: %v", p, err)
		}
		if err := fw.Add(filepath.Clean(p)); err != nil {
			log.Printf("Failed to add watch directory %s: %v", p, err)
		}
	}

	w := &Watcher{
		fw:       fw,
		onChange: onChange,
	}

	go w.watch()
	return w, nil
}

func (w *Watcher) watch() {
	// Debounce timer coalesces rapid filesystem events into a single reload.
	// The timer fires only after the configured quiet period with no new events. (M3 fix)
	const debounceInterval = 2 * time.Second
	debounce := time.NewTimer(0)
	debounce.Stop() // Start stopped; only arm on actual events

	for {
		select {
		case event, ok := <-w.fw.Events:
			if !ok {
				return
			}
			// Only trigger on write/create/remove/rename
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				log.Printf("Detected file change: %s. Scheduling reload...", event.Name)
				debounce.Reset(debounceInterval)
			}
		case <-debounce.C:
			log.Println("Debounce period elapsed, triggering reload...")
			w.onChange()
		case err, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (w *Watcher) Close() error {
	return w.fw.Close()
}
