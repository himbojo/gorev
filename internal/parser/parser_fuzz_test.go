package parser

import (
	"os"
	"testing"
)

func FuzzLoadCRL(f *testing.F) {
	// Add seed corpus from existing test-data if available
	f.Add([]byte("-----BEGIN X509 CRL-----\nMII..."))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary file to use with LoadCRL
		tmpfile, err := os.CreateTemp("", "fuzz-crl-*")
		if err != nil {
			return
		}
		defer os.Remove(tmpfile.Name())
		
		if _, err := tmpfile.Write(data); err != nil {
			return
		}
		tmpfile.Close()

		// LoadCRL should not panic
		_, _ = LoadCRL(tmpfile.Name())
	})
}

func FuzzLoadCA(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		tmpfile, err := os.CreateTemp("", "fuzz-ca-*")
		if err != nil {
			return
		}
		defer os.Remove(tmpfile.Name())
		
		if _, err := tmpfile.Write(data); err != nil {
			return
		}
		tmpfile.Close()

		// LoadCA should not panic
		_, _ = LoadCA(tmpfile.Name())
	})
}
