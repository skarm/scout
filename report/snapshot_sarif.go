package report

import (
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"strings"
)

const (
	sarifFindingPersistent = "persistent"
	snapshotURIBaseID      = "SCOUTROOT"
)

const (
	// SnapshotChangeAdded marks a root present only in the candidate snapshot.
	SnapshotChangeAdded = "added"
	// SnapshotChangeRemoved marks a root present only in the reference snapshot.
	SnapshotChangeRemoved = "removed"
	// SnapshotChangeModified marks a root whose captured contents changed.
	SnapshotChangeModified = "modified"
	// SnapshotChangeUnchanged marks a root present with equal contents on both sides.
	SnapshotChangeUnchanged = "unchanged"
)

// SnapshotSARIFRoot identifies the original locations and the sealed report
// for one root of an environment snapshot comparison.
type SnapshotSARIFRoot struct {
	ID, Change, BeforePath, AfterPath string
	Document                          Document
}

type snapshotSARIFRoot struct {
	ID         string                  `json:"id"`
	Change     string                  `json:"change"`
	BeforePath string                  `json:"beforePath,omitempty"`
	AfterPath  string                  `json:"afterPath,omitempty"`
	Report     sarifDocumentProperties `json:"report"`
	Reference  []run                   `json:"referenceRuns,omitempty"`
}

type snapshotSARIFProperties struct {
	Comparison map[string]any      `json:"environmentComparison"`
	Roots      []snapshotSARIFRoot `json:"roots"`
}

// WriteSnapshotComparisonSARIF writes candidate findings as SARIF results.
// Reference findings are retained in the root property bags as historical
// evidence. Properties contains the caller's environment comparison metadata.
func WriteSnapshotComparisonSARIF(w io.Writer, roots []SnapshotSARIFRoot, properties map[string]any) error {
	if w == nil {
		return errors.New("nil report writer")
	}

	log := sarif{
		Schema: sarifSchemaURI, Version: sarifVersion, Runs: []run{},
	}
	metadata := make([]snapshotSARIFRoot, 0, len(roots))

	for _, root := range roots {
		document, err := root.Document.validated()
		if err != nil {
			return err
		}

		part := documentToSARIF(document)
		summary := snapshotSARIFRoot{ID: root.ID, Change: root.Change, BeforePath: root.BeforePath, AfterPath: root.AfterPath, Report: part.Properties}

		for i, item := range part.Runs {
			target := document.Run.Targets[i]
			item.Properties["snapshotRootID"] = root.ID
			item.Properties["snapshotRootChange"] = root.Change

			if root.Change == SnapshotChangeRemoved || target.Role == "before" {
				item.Properties["snapshotSide"] = "reference"
				applySnapshotURIBase(&item, root.BeforePath, target.Analysis.Artifact.SourceKind)
				summary.Reference = append(summary.Reference, item)

				continue
			}

			item.Properties["snapshotSide"] = "candidate"
			applySnapshotURIBase(&item, root.AfterPath, target.Analysis.Artifact.SourceKind)
			applySnapshotFindingChanges(item.Results, root.Change, part.Properties.Comparison)
			log.Runs = append(log.Runs, item)
		}

		metadata = append(metadata, summary)
	}

	return writeEncodedDocument(w, struct {
		sarif
		Properties snapshotSARIFProperties `json:"properties"`
	}{log, snapshotSARIFProperties{Comparison: properties, Roots: metadata}})
}

func applySnapshotFindingChanges(results *[]result, rootChange string, delta *UpdateDelta) {
	if results == nil {
		return
	}

	changes := map[string]string{}

	if delta != nil {
		for _, change := range delta.Findings {
			if change.AfterID != "" {
				changes[change.AfterID] = change.Change
			}
		}
	}

	for i := range *results {
		item := &(*results)[i]

		id, static := item.PartialFingerprints[sarifOccurrenceFingerprint]
		if !static {
			continue
		}

		change := changes[id]
		if change == "" {
			switch {
			case rootChange == SnapshotChangeAdded:
				change = UpdateIntroduced
			case delta != nil && delta.Completeness == Complete:
				change = sarifFindingPersistent
			default:
				change = UpdateUnverified
			}
		}

		item.Properties["findingChange"] = change
		switch change {
		case UpdateIntroduced:
			item.BaselineState = "new"
		case sarifFindingPersistent:
			item.BaselineState = "unchanged"
		case UpdateRelocated, UpdateContextChanged:
			item.BaselineState = "updated"
		}
	}
}

func applySnapshotURIBase(item *run, path, kind string) {
	if !filepath.IsAbs(path) {
		return
	}

	if kind == "file" {
		path = filepath.Dir(path)
	}

	path = filepath.ToSlash(path)
	uri := url.URL{Scheme: "file", Path: strings.TrimRight(path, "/") + "/"}

	if strings.HasPrefix(path, "//") {
		uri.Host, uri.Path, _ = strings.Cut(strings.TrimPrefix(uri.Path, "//"), "/")
		uri.Path = "/" + uri.Path
	} else if !strings.HasPrefix(path, "/") {
		uri.Path = "/" + uri.Path
	}

	item.OriginalURIBaseIDs = map[string]artifactLocation{snapshotURIBaseID: {URI: uri.String()}}
	if item.Results != nil {
		for i := range *item.Results {
			finding := &(*item.Results)[i]
			setSnapshotURIBase(finding.Locations)

			for _, flow := range finding.CodeFlows {
				for _, thread := range flow.ThreadFlows {
					for i := range thread.Locations {
						setSnapshotLocationBase(&thread.Locations[i].Location)
					}
				}
			}
		}
	}

	for _, invocation := range item.Invocations {
		for _, n := range invocation.ToolExecutionNotifications {
			setSnapshotURIBase(n.Locations)
		}
	}
}

func setSnapshotURIBase(locations []location) {
	for i := range locations {
		setSnapshotLocationBase(&locations[i])
	}
}

func setSnapshotLocationBase(loc *location) {
	if a := &loc.PhysicalLocation.ArtifactLocation; !strings.HasPrefix(a.URI, ObjectPathPrefix) {
		a.URIBaseID = snapshotURIBaseID
	}
}
