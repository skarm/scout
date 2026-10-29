package update

import (
	"encoding/json"
	"sort"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

type object struct {
	key     string
	address report.ObjectAddress
	file    report.File
}
type inventory struct {
	byPath   map[string]*object
	byKey    map[string]*object
	complete bool
}

func (x inventory) objectKey(path string) string {
	if o := x.byPath[path]; o != nil {
		return o.key
	}
	// Never merge an unresolved object with an unrelated valid locator.
	return key("unresolved", path)
}

func (b *builder) inventory(r report.Analysis, single bool) inventory {
	out := inventory{byPath: map[string]*object{}, byKey: map[string]*object{}, complete: r.Artifact.InventoryComplete}

	for _, f := range r.Artifact.Files {
		if !b.step() {
			out.complete = false
			return out
		}

		a := report.ObjectAddress{Root: f.Path}
		if single {
			a = report.ObjectAddress{SingleFile: true}
		}

		b.putObject(&out, f, a)
	}
	// Extractor output is normally BFS. Sort by depth so content-addressed URI
	// ordering never becomes a hidden parent-before-child assumption.
	derived := append([]report.DerivedObject(nil), r.Extraction.Objects...)
	sort.Slice(derived, func(i, j int) bool {
		if derived[i].Depth != derived[j].Depth {
			return derived[i].Depth < derived[j].Depth
		}

		return derived[i].File.Path < derived[j].File.Path
	})

	for _, d := range derived {
		if !b.step() {
			out.complete = false
			return out
		}

		b.putDerivedObject(&out, d)
	}

	if !extractionComplete(r.Extraction) {
		out.complete = false
	}

	return out
}

func (b *builder) putDerivedObject(out *inventory, d report.DerivedObject) {
	p := out.byPath[d.ParentPath]
	if p == nil || p.file.SHA256 != d.ParentSHA256 {
		out.complete = false

		b.issue("unresolved_object_provenance")

		return
	}

	a := report.ObjectAddress{
		SingleFile: p.address.SingleFile,
		Root:       p.address.Root,
		Steps:      append([]report.ObjectStep(nil), p.address.Steps...),
	}

	s := report.ObjectStep{
		Role:             d.Role,
		Extractor:        d.ExtractorID,
		ExtractorVersion: d.ExtractorVersion,
		Member:           d.MemberName,
		Ordinal:          d.Ordinal,
	}
	if d.Role == "archive_member" {
		s.Ordinal = 0
	}

	a.Steps = append(a.Steps, s)
	b.putObject(out, d.File, a)
}

func (b *builder) putObject(out *inventory, f report.File, a report.ObjectAddress) {
	id := digest(a)
	if out.byKey[id] != nil || out.byPath[f.Path] != nil {
		out.complete = false

		b.issue("ambiguous_object_identity")

		return
	}

	o := &object{key: id, address: a, file: f}

	out.byKey[id], out.byPath[f.Path] = o, o
	if f.Status != report.CaptureCaptured || f.SHA256 == "" {
		out.complete = false
	}
}

func (b *builder) files() {
	for _, id := range sortedKeys(b.old.byKey, b.next.byKey) {
		if !b.step() {
			return
		}

		a, z := b.old.byKey[id], b.next.byKey[id]
		c := fileChangeSides(id, a, z)

		c.Change = objectPresenceChange(a, z, b.old.complete, b.next.complete)
		if c.Change == "" {
			c.Reasons = fileChangeReasons(a.file, z.file, c.Address)
			if len(c.Reasons) == 0 {
				b.delta.Counts.UnchangedObjects++
				continue
			}

			c.Change = "modified"
			if len(c.Reasons) == 1 && c.Reasons[0] == "input_name_changed" {
				c.Change = "renamed_input"
			}
		}

		if c.Change == "unverified" {
			b.issue("object_delta_unverified")

			c.Reasons = append(c.Reasons, "inventory_or_content_unavailable")
		}

		b.delta.Counts.FileChanges++
		if b.retain() {
			b.delta.Files = append(b.delta.Files, c)
		}
	}
}

func extractionComplete(r report.ExtractionReport) bool {
	if len(r.Skipped) > 0 {
		return false
	}

	for _, step := range r.Steps {
		if step.Status != report.OutcomeCompleted {
			return false
		}
	}

	return true
}

func fileChangeSides(id string, before, after *object) report.FileChange {
	c := report.FileChange{ObjectID: id, Reasons: []string{}}

	if before != nil {
		f := before.file
		c.Before = &f
		c.Address = before.address
	}

	if after != nil {
		f := after.file
		c.After = &f
		c.Address = after.address
	}

	return c
}

func objectPresenceChange(before, after *object, oldComplete, newComplete bool) string {
	for _, o := range []*object{before, after} {
		if o != nil && o.file.Status != report.CaptureCaptured {
			return "unverified"
		}
	}

	switch {
	case before == nil:
		if !oldComplete {
			return "unverified"
		}

		return "added"
	case after == nil:
		if !newComplete {
			return "unverified"
		}

		return "removed"
	default:
		return ""
	}
}

func fileChangeReasons(before, after report.File, address report.ObjectAddress) []string {
	reasons := make([]string, 0)
	if before.SHA256 != after.SHA256 || before.Size != after.Size {
		reasons = append(reasons, "content_changed")
	}

	if before.Executable != after.Executable {
		reasons = append(reasons, "executable_mode_changed")
	}

	if before.Kind != after.Kind {
		reasons = append(reasons, "content_classification_changed")
	}

	if address.SingleFile && len(address.Steps) == 0 && before.Path != after.Path {
		reasons = append(reasons, "input_name_changed")
	}

	return reasons
}

func digest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("update identity contains unsupported internal value")
	}

	return artifact.Hash(b)
}
func key(parts ...string) string { return digest(parts) }
func standalone(r report.Analysis) bool {
	return (r.Artifact.SourceKind == "file" || r.Artifact.SourceKind == "memory") && len(r.Artifact.Files) == 1
}

func sortedKeys[T any](a, b map[string]T) []string {
	set := make(map[string]bool, len(a)+len(b))
	for k := range a {
		set[k] = true
	}

	for k := range b {
		set[k] = true
	}

	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func spanKey(s *report.SourceRef, x inventory) string {
	if s == nil {
		return key("no_source")
	}

	return key(x.objectKey(s.Path), s.SpanSHA256)
}

func locationKey(f report.Finding, x inventory) string {
	trace := make([]string, 0, len(f.Trace))
	for _, t := range f.Trace {
		trace = append(trace, key(t.Role, x.objectKey(t.Location.Path), t.Evidence.SpanSHA256))
	}

	related := make([]string, 0, len(f.RelatedEvidence))
	for _, r := range f.RelatedEvidence {
		related = append(related, key(x.objectKey(r.Path), r.SpanSHA256))
	}

	return key(x.objectKey(f.Location.Path), f.RuleID, f.RuleVersion, string(f.Severity), f.Category, f.Method, f.Evidence.SpanSHA256, digest(trace), digest(related), digest(f.AdvisoryIDs), digest(f.SignatureNames))
}
