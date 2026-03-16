package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileStatus holds metadata about a file's import result.
type FileStatus struct {
	Status  string // e.g., "LOADED", "FAILED", "SKIPPED"
	Purpose string // e.g., "CA Certificate", "OCSP Responder Key"
}

// GenerateTree recursively walks the given directory and returns a string
// representing the directory structure as a tree. It optionally enriches
// file names with status and purpose from the provided statuses map.
func GenerateTree(root string, statuses map[string]FileStatus) (string, error) {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s/\n", filepath.Base(root)))
	err := buildTree(root, "", &builder, statuses)
	return builder.String(), err
}

func buildTree(path string, prefix string, builder *strings.Builder, statuses map[string]FileStatus) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	// Filter out hidden files
	var filtered []os.DirEntry
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			filtered = append(filtered, entry)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Name() < filtered[j].Name()
	})

	for i, entry := range filtered {
		isLast := i == len(filtered)-1
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		fullPath := filepath.Join(path, entry.Name())
		line := entry.Name()
		if !entry.IsDir() {
			if stat, ok := statuses[fullPath]; ok {
				statusPart := ""
				if stat.Status != "" {
					statusPart = fmt.Sprintf(" [%s]", stat.Status)
				}
				purposePart := ""
				if stat.Purpose != "" {
					purposePart = fmt.Sprintf(" (%s)", stat.Purpose)
				}
				line = fmt.Sprintf("%s%s%s", line, statusPart, purposePart)
			}
		}

		builder.WriteString(fmt.Sprintf("%s%s%s\n", prefix, connector, line))

		if entry.IsDir() {
			newPrefix := prefix + "│   "
			if isLast {
				newPrefix = prefix + "    "
			}
			if err := buildTree(filepath.Join(path, entry.Name()), newPrefix, builder, statuses); err != nil {
				return err
			}
		}
	}

	return nil
}

// ImportSummary holds metadata about what was loaded.
type ImportSummary struct {
	CACerts      int
	ResponderPairs int
	CRLs         int
	Revocations  int
}

// FormatImportSummary returns a human-readable summary of the loaded assets.
func FormatImportSummary(s ImportSummary) string {
	var sb strings.Builder
	sb.WriteString("\n📋 Import Summary:\n")
	sb.WriteString(fmt.Sprintf("  - CA Certificates: %d\n", s.CACerts))
	sb.WriteString(fmt.Sprintf("  - Responder Pairs: %d\n", s.ResponderPairs))
	sb.WriteString(fmt.Sprintf("  - CRLs Processed:  %d\n", s.CRLs))
	sb.WriteString(fmt.Sprintf("  - Total Revocations: %d\n", s.Revocations))
	
	if s.CACerts == 0 || s.ResponderPairs == 0 || s.CRLs == 0 {
		sb.WriteString("\n⚠️  Warnings:\n")
		if s.CACerts == 0 {
			sb.WriteString("    - No CA certificates loaded. Responder will not function.\n")
		}
		if s.ResponderPairs == 0 {
			sb.WriteString("    - No signed responder pairs found. OCSP signing disabled.\n")
		}
		if s.CRLs == 0 {
			sb.WriteString("    - No CRLs processed. Revocation status unknown.\n")
		}
	}
	
	return sb.String()
}
