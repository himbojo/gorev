package watcher

import (
	"log"
	"os"
	"path/filepath"

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
	for {
		select {
		case event, ok := <-w.fw.Events:
			if !ok {
				return
			}
			// Only trigger on write/create/remove/rename
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				log.Printf("Detected file change: %s. Triggering reload...", event.Name)
				w.onChange()
			}
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
