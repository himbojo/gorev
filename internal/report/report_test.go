package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateTree(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create a mock directory structure
	dirs := []string{"cas", "responders", "crls"}
	for _, d := range dirs {
		if err := os.Mkdir(filepath.Join(tmpDir, d), 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}
	
	files := []string{
		filepath.Join("cas", "root.crt"),
		filepath.Join("responders", "resp.crt"),
		filepath.Join("responders", "resp.key"),
		filepath.Join("crls", "test.crl"),
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file %s: %v", f, err)
		}
	}

	// Test with statuses
	statuses := map[string]FileStatus{
		filepath.Join(tmpDir, "cas", "root.crt"):        {Status: "LOADED", Purpose: "CA Certificate"},
		filepath.Join(tmpDir, "responders", "resp.key"): {Status: "FAILED", Purpose: "Responder Key"},
	}

	tree, err := GenerateTree(tmpDir, statuses)
	if err != nil {
		t.Fatalf("GenerateTree failed: %v", err)
	}

	// Basic checks on the output
	expectedParts := []string{
		"cas",
		"root.crt [LOADED] (CA Certificate)",
		"responders",
		"resp.crt",
		"resp.key [FAILED] (Responder Key)",
		"crls",
		"test.crl",
	}

	for _, part := range expectedParts {
		if !strings.Contains(tree, part) {
			t.Errorf("expected tree to contain %q, but it didn't", part)
		}
	}
}

func TestFormatImportSummary(t *testing.T) {
	summary := ImportSummary{
		CACerts:        2,
		ResponderPairs: 1,
		CRLs:           3,
		Revocations:    150,
	}

	output := FormatImportSummary(summary)
	
	expectedParts := []string{
		"Import Summary",
		"CA Certificates: 2",
		"Responder Pairs: 1",
		"CRLs Processed:  3",
		"Total Revocations: 150",
	}

	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("expected summary output to contain %q", part)
		}
	}

	t.Run("Warning case", func(t *testing.T) {
		emptySummary := ImportSummary{}
		output := FormatImportSummary(emptySummary)
		if !strings.Contains(output, "Warnings") {
			t.Error("expected output to contain 'Warnings' for empty summary")
		}
		if !strings.Contains(output, "No CA certificates loaded") {
			t.Error("expected output to contain CA warning")
		}
	})
}
