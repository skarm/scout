package envcompare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/skarm/scout/report"
)

// Write renders a comparison in a supported report format.
func (r Comparison) Write(w io.Writer, format report.Format) error {
	switch format {
	case report.JSON:
		return json.NewEncoder(w).Encode(r)
	case report.SARIF:
		return r.writeSARIF(w)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "Environment changes: decision=%s; exit=%d.\n\n", r.Decision, r.Code)
	fmt.Fprintln(&b, relationshipSummary(r.Relationships))
	b.WriteString("\n")
	fmt.Fprintf(&b, "Saved content: %s\nCurrent content: %s\n\n", r.Before, r.After)

	if r.Code == 2 {
		b.WriteString("Coverage is incomplete. Unobserved findings do not prove remediation.\n\n")
	}

	r.writeRootSummary(&b, format)
	r.writeRelationshipSummary(&b, format)

	b.WriteString("Root identifiers are operator-selected boundaries; activation is not inferred. Both versions were rescanned with the current configuration.\n\n")

	for _, root := range r.Roots {
		if root.Change == "unchanged" && root.Report.Run.State == report.RunComplete && root.Report.Evaluation.Decision == report.Allow {
			continue
		}

		label := "evidence and policy"
		if root.Change == "removed" {
			label = "historical evidence only; removed from candidate"
		}

		fmt.Fprintf(&b, "Root %s — %s\n\n", strconv.QuoteToASCII(root.ID), label)

		if err := report.Write(&b, format, root.Report); err != nil {
			return err
		}
	}

	if r.Environment != nil && (r.Environment.Run.State != report.RunComplete || len(r.Environment.Run.Environment.Observations) > 0) {
		b.WriteString("Current environment — relationships and policy\n\n")

		if err := report.Write(&b, format, *r.Environment); err != nil {
			return err
		}
	}

	_, err := w.Write(b.Bytes())

	return err
}

// Quote source-owned paths as Markdown code spans, including embedded backticks.
func quoteSnapshotPath(value string, format report.Format) string {
	escaped := strconv.QuoteToASCII(value)
	if format != report.Markdown {
		return escaped
	}

	delimiter := "`"
	for strings.Contains(escaped, delimiter) {
		delimiter += "`"
	}

	return delimiter + escaped + delimiter
}

func evidenceRoot(doc *report.Document, id string, roots []environmentRootChange, previous bool) string {
	ids := []string{}

	for _, root := range roots {
		if previous && root.Change != "added" || !previous && root.Change != "removed" {
			ids = append(ids, root.ID)
		}
	}

	if doc != nil {
		for _, target := range doc.Run.Targets {
			if target.ID == id {
				if target.Index < len(ids) {
					return ids[target.Index]
				}

				return target.ID
			}
		}
	}

	return id
}

func (r Comparison) writeRootSummary(b *bytes.Buffer, format report.Format) {
	for _, root := range r.Roots {
		fmt.Fprintf(b, "Root %s: %s", strconv.QuoteToASCII(root.ID), root.Change)

		source := root.AfterPath
		if source == "" {
			source = root.BeforePath
		}

		fmt.Fprintf(b, "; source %s", quoteSnapshotPath(source, format))

		if d := root.Report.Run.Comparison; d != nil {
			fmt.Fprintf(b, "; %d file changes, %d component changes, %d dependency changes, %d new findings", d.Counts.FileChanges, d.Counts.ComponentChanges, d.Counts.DependencyChanges, d.Counts.IntroducedFindings)
		}

		b.WriteString(".\n\n")

		for _, content := range root.Content {
			fmt.Fprintf(b, "%s: %s (%d -> %d bytes). %s", quoteSnapshotPath(content.Path, format), content.Change, content.BeforeBytes, content.AfterBytes, content.Explanation)

			if content.Text {
				fmt.Fprintf(b, " Changed line ranges contain %d removed and %d added lines.", content.RemovedLines, content.AddedLines)
			}

			b.WriteString("\n\n")

			if content.Excerpt != "" {
				writeSourceExcerpt(b, content.Excerpt, format)
			}

			if content.DiffOmitted {
				b.WriteString("Source excerpt omitted or truncated by the text/size limits. See the coverage diagnostics for analysis status.\n\n")
			}
		}

		for _, directory := range root.Directories {
			fmt.Fprintf(b, "Directory %s: %s.\n\n", quoteSnapshotPath(directory.Path, format), directory.Change)
		}
	}
}

func (r Comparison) writeRelationshipSummary(b *bytes.Buffer, format report.Format) {
	for _, change := range r.Relationships.Changes {
		if change.Change == "persistent" {
			continue
		}

		observation := change.After
		if observation == nil {
			observation = change.Before
		}

		fmt.Fprintf(b, "Relationship %s: %s. %s", change.Kind, change.Change, relationshipExplanation(change.Kind))

		if observation.SimilarityBasisPoints != 0 {
			fmt.Fprintf(b, " Description similarity: %.2f%%.", float64(observation.SimilarityBasisPoints)/100)
		}

		b.WriteString("\n\n")

		doc := r.Environment
		if change.After == nil {
			doc = r.PreviousEnvironment
		}

		for _, ref := range observation.Evidence {
			fmt.Fprintf(b, "Evidence: %s, %s, bytes %d..%d.\n\n", quoteSnapshotPath(evidenceRoot(doc, ref.TargetID, r.Roots, change.After == nil), format), quoteSnapshotPath(ref.Source.Path, format), ref.Source.ByteStart, ref.Source.ByteEnd)
		}
	}
}
