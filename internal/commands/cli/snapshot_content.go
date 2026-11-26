package cli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/capture/envsnapshot"
	"github.com/skarm/scout/report"
)

const (
	snapshotDiffBytes     = 64 << 10
	snapshotDiffLines     = 400
	snapshotDiffFileBytes = 128 << 10
)

type snapshotContentChange struct {
	Path         string `json:"path"`
	Change       string `json:"change"`
	Explanation  string `json:"explanation"`
	Excerpt      string `json:"excerpt,omitempty"`
	BeforeBytes  int    `json:"before_bytes"`
	AfterBytes   int    `json:"after_bytes"`
	RemovedLines int    `json:"removed_lines,omitempty"`
	AddedLines   int    `json:"added_lines,omitempty"`
	Text         bool   `json:"text"`
	DiffOmitted  bool   `json:"diff_omitted,omitempty"`
}

func rootFiles(s envsnapshot.Snapshot, id string) (map[string]envsnapshot.Entry, string) {
	files := map[string]envsnapshot.Entry{}

	root := s.Root(id)

	for _, entry := range root.Entries {
		if !entry.Directory {
			files[entry.Path] = entry
		}
	}

	return files, root.Source
}

func (r *environmentComparison) describeContent(before, after envsnapshot.Snapshot, includeSource bool) {
	byteBudget, lineBudget := snapshotDiffBytes, snapshotDiffLines

	for i := range r.Roots {
		root := &r.Roots[i]
		old, oldPath := rootFiles(before, root.ID)
		next, newPath := rootFiles(after, root.ID)
		root.BeforePath, root.AfterPath = oldPath, newPath

		keys := map[string]string{}
		for path := range old {
			keys[path] = ""
		}

		for path := range next {
			keys[path] = ""
		}

		for _, path := range sortedRootIDs(keys, nil) {
			b, bok := old[path]

			a, aok := next[path]
			if bok && aok && b.SHA256 == a.SHA256 && b.Executable == a.Executable {
				continue
			}

			item := describeSnapshotFile(path, b, a, bok, aok, includeSource, &byteBudget, &lineBudget)

			root.Content = append(root.Content, item)
		}
	}
}

func isSnapshotText(data []byte) bool {
	return len(data) <= snapshotDiffFileBytes && utf8.Valid(data) && !bytes.ContainsRune(data, 0)
}

func snapshotLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	lines := strings.SplitAfter(string(data), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return lines
}

func commonLines(before, after []string) (int, int) {
	prefix := 0
	for prefix < min(len(before), len(after)) && before[prefix] == after[prefix] {
		prefix++
	}

	suffix := 0
	for suffix < min(len(before), len(after))-prefix && before[len(before)-1-suffix] == after[len(after)-1-suffix] {
		suffix++
	}

	return prefix, suffix
}

// A bounded excerpt is deliberately not an applyable patch. Quoting each source
// line prevents terminal controls from becoming commands or changing report layout.
func sourceExcerpt(before, after []string, start, end int, byteBudget, lineBudget *int) (string, bool) {
	if len(before)-start-end == 0 && len(after)-start-end == 0 {
		return "", false
	}

	var b strings.Builder

	omitted := false
	appendLine := func(prefix, line string) {
		quoted := prefix + strconv.QuoteToASCII(strings.TrimSuffix(line, "\n"))
		if prefix != "@ " && !strings.HasSuffix(line, "\n") {
			quoted += " [no trailing newline]"
		}

		quoted += "\n"
		if *lineBudget <= 0 || len(quoted) > *byteBudget {
			omitted = true
			return
		}

		b.WriteString(quoted)

		*lineBudget--
		*byteBudget -= len(quoted)
	}
	appendLine("@ ", fmt.Sprintf("old start=%d count=%d; new start=%d count=%d", start+1, len(before)-start-end, start+1, len(after)-start-end))

	for _, line := range before[start : len(before)-end] {
		appendLine("- ", line)
	}

	for _, line := range after[start : len(after)-end] {
		appendLine("+ ", line)
	}

	return b.String(), omitted
}

func contentExplanation(path, change string) string {
	if change == "removed" {
		return "Captured file removed from the selected environment; this does not prove remediation."
	}

	action := "changed"
	if change == "added" {
		action = "added"
	}

	switch strings.ToLower(filepath.Base(path)) {
	case "skill.md", "agents.md", "claude.md":
		return "Agent instructions " + action + "; review the tasks, authority and tool use they request."
	case "requirements.txt", "go.mod", "go.sum", "package.json", "package-lock.json", "pyproject.toml", "uv.lock", "cargo.toml", "cargo.lock":
		return "Dependency declarations " + action + "; review package names, versions and install behavior."
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".go", ".ps1":
		return "Executable source " + action + "; review process execution, file access and network operations."
	case ".json", ".toml", ".yaml", ".yml":
		return "Configuration " + action + "; review declarations, commands and permissions."
	default:
		return "Captured content " + action + "; inspect the change before accepting the new environment."
	}
}

func writeSourceExcerpt(b *bytes.Buffer, text string, format report.Format) {
	if format != report.Markdown {
		b.WriteString(text)
		b.WriteString("\n")

		return
	}

	fence := "```"
	for strings.Contains(text, fence) {
		fence += "`"
	}

	fmt.Fprintf(b, "%stext\n%s%s\n\n", fence, text, fence)
}

func describeSnapshotFile(path string, b, a envsnapshot.Entry, bok, aok, includeSource bool, byteBudget, lineBudget *int) snapshotContentChange {
	change := "modified"
	if !bok {
		change = "added"
	}

	if !aok {
		change = "removed"
	}

	item := snapshotContentChange{Path: path, Change: change, BeforeBytes: len(b.Data), AfterBytes: len(a.Data), Explanation: contentExplanation(path, change)}
	if bok && aok && b.Executable != a.Executable {
		item.Explanation += " Executable permission bits changed."
	}

	item.Text = isSnapshotText(b.Data) && isSnapshotText(a.Data)
	if item.Text {
		beforeLines, afterLines := snapshotLines(b.Data), snapshotLines(a.Data)
		start, end := commonLines(beforeLines, afterLines)
		item.RemovedLines = len(beforeLines) - start - end

		item.AddedLines = len(afterLines) - start - end
		if includeSource {
			item.Excerpt, item.DiffOmitted = sourceExcerpt(beforeLines, afterLines, start, end, byteBudget, lineBudget)
		}
	} else if includeSource {
		item.DiffOmitted = true
	}

	return item
}
