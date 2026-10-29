package maintenance

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/skarm/scout/internal/dev/replaywire"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

//nolint:gochecknoglobals // Immutable correspondence between upstream families and replay summary groups.
var suiteFamilies = map[string]string{
	"PI001":   "P1",
	"PL001":   "P6",
	"AC003":   "BH1",
	"NV-TR1M": "TR1",
	"NV-TR2M": "TR2",
	"NV-TR3M": "TR3",
	"NV-TR1":  "NV-TR1",
	"NV-TR2":  "NV-TR2",
	"NV-TR3":  "NV-TR3",
	"NV-SC7M": "NV-SC7M",
}

//nolint:gochecknoglobals // Immutable ASCII escapes required by the upstream JSON wire encoding.
var asciiEscapes = map[rune]string{'"': `\"`, '\\': `\\`, '\b': `\b`, '\f': `\f`, '\n': `\n`, '\r': `\r`, '\t': `\t`}

type capturedBlob struct {
	SHA256         string `json:"sha256,omitempty"`
	Bytes          int    `json:"bytes"`
	Representation string `json:"representation,omitempty"`
	Omitted        string `json:"omitted,omitempty"`
}
type capturedObservation struct {
	ID, Test, Phase, Module, Function string
	Files                             map[string]capturedBlob
	ContextFlags                      []string                `json:"context_flags"`
	UpstreamFindings                  []struct{ Rule string } `json:"upstream_findings"`
	Families                          []string
}
type replayGroup struct {
	ID           string                  `json:"id"`
	Files        map[string]capturedBlob `json:"files"`
	Observations []string                `json:"observations"`
}
type replayIndex struct {
	CaptureSummary json.RawMessage `json:"capture_summary"`
	Groups         []replayGroup   `json:"groups"`
	Excluded       []object        `json:"excluded"`
}
type replayResult = replaywire.Record

type replayDifference struct {
	Observation  string                  `json:"observation"`
	Test         string                  `json:"test"`
	Input        string                  `json:"input"`
	Module       string                  `json:"module"`
	Function     string                  `json:"function"`
	Missing      []string                `json:"missing"`
	Extra        []string                `json:"extra"`
	BoundaryKind string                  `json:"boundary_kind"`
	Wanted       []string                `json:"wanted"`
	Found        []string                `json:"found"`
	Files        map[string]capturedBlob `json:"files"`
	ContextFlags []string                `json:"context_flags"`
	Coverage     string                  `json:"coverage"`
	Diagnostics  []string                `json:"diagnostics"`
	Error        *string                 `json:"error"`
}
type suiteComparison struct {
	ScannedInputs         int                `json:"scanned_inputs"`
	DifferingObservations int                `json:"differing_observations"`
	Missing               map[string]int     `json:"missing_observation_counts"`
	Extra                 map[string]int     `json:"extra_observation_counts"`
	Positive              map[string]int     `json:"positive_observation_counts"`
	PrimaryMissing        map[string]int     `json:"public_or_direct_missing_counts"`
	PrimaryExtra          map[string]int     `json:"public_or_direct_extra_counts"`
	Errors                map[string]int     `json:"replay_errors"`
	Decisions             map[string]int     `json:"decisions"`
	Coverage              map[string]int     `json:"coverage"`
	Differences           []replayDifference `json:"differences"`
}

type suitePreparation struct {
	index        replayIndex
	observations map[string]capturedObservation
	positions    map[string]int
}

type suiteReplayComparison struct {
	groups       map[string]replayGroup
	observations map[string]capturedObservation
	seen         map[string]bool
	summary      suiteComparison
}

func compareUpstreamSuite(ctx context.Context, o options, w io.Writer) error {
	if err := o.require("capture", "replay"); err != nil {
		return err
	}

	switch o.mode {
	case "prepare":
		return prepareSuite(ctx, o.get("capture"), o.get("replay"), w)
	case "compare":
		if err := o.require("results", "output"); err != nil {
			return err
		}

		return compareSuite(ctx, o.get("capture"), o.get("replay"), o.get("results"), o.get("output"), w)
	default:
		return errors.New("compare-upstream-suite requires prepare or compare")
	}
}

func readJSONLines[T any](ctx context.Context, path string, visit func(T) error) error {
	f, err := os.Open(path) //nolint:gosec // G304: explicit caller-selected saved evidence stream.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), maxJSONLine)

	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			return err
		}

		var row T
		if err = json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return err
		}

		if err = visit(row); err != nil {
			return err
		}
	}

	return scanner.Err()
}

func prepareSuite(ctx context.Context, capture, output string, w io.Writer) error {
	summary, err := readCaptureSummary(ctx, filepath.Join(capture, "capture-summary.json"))
	if err != nil {
		return err
	}

	if err := newOutput(output); err != nil {
		return err
	}

	builder := suitePreparation{
		index: replayIndex{
			CaptureSummary: summary,
			Groups:         []replayGroup{},
			Excluded:       []object{},
		},
		observations: map[string]capturedObservation{},
		positions:    map[string]int{},
	}
	if err := readJSONLines(ctx, filepath.Join(capture, "observations.jsonl"), builder.add); err != nil {
		return err
	}

	index, observations := builder.index, builder.observations

	if err := writeReplayInputs(capture, output, index.Groups); err != nil {
		return err
	}

	tests, counts, err := indexSuiteTests(ctx, capture, observations, index)
	if err != nil {
		return err
	}

	if err := writeSuiteIndex(output, index, tests, counts); err != nil {
		return err
	}

	return printJSON(w, counts)
}

// Preserve the source summary as data, after one exact-key JSON admission.
// Wrong or absent scalar types must never become a successful zero exit code.
func readCaptureSummary(ctx context.Context, path string) (json.RawMessage, error) {
	//nolint:gosec // G304: explicit operator-selected evidence file, admitted below with byte and schema limits.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // Read-only evidence: report the read/admission error, not cleanup failure.

	data, err := io.ReadAll(io.LimitReader(f, jsonconfig.MaxBytes+1))
	if err != nil {
		return nil, err
	}

	root, err := jsonconfig.Parse(ctx, string(data))
	if err != nil {
		return nil, err
	}

	exit, failures := root.GetOrEmpty("exit_status"), root.GetOrEmpty("capture_errors")
	if exit.Kind != jsonconfig.KindNumber || failures.Kind != jsonconfig.KindArray {
		return nil, errors.New("invalid capture summary schema")
	}

	if exit.String != "0" && exit.String != "-0" || len(failures.Elements) != 0 {
		return nil, errors.New("capture did not complete cleanly")
	}

	return data, nil
}

func replayExclusion(files map[string]capturedBlob) string {
	total := 0

	for _, name := range sortedKeys(files) {
		item := files[name]

		if reason := replayFileExclusion(name, item); reason != "" {
			return reason
		}

		total += item.Bytes
	}

	if total > 16<<20 || len(files) > 1024 {
		return "replay_input_limit"
	}

	return ""
}

func writeReplayInputs(capture, output string, groups []replayGroup) (err error) {
	f, err := os.OpenFile(filepath.Join(output, "input.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: fixed filename in a fresh caller-selected output directory.
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	enc := json.NewEncoder(f)

	for _, g := range groups {
		files := make([]struct {
			Name string `json:"name"`
			Data []byte `json:"data"`
		}, 0, len(g.Files))
		for _, name := range sortedKeys(g.Files) {
			item := g.Files[name]

			data, e := readCapturedBlob(capture, item)
			if e != nil {
				return e
			}

			files = append(files, struct {
				Name string `json:"name"`
				Data []byte `json:"data"`
			}{Name: name, Data: data})
		}

		if err = enc.Encode(object{"id": g.ID, "files": files}); err != nil {
			return err
		}
	}

	return nil
}

func readCapturedBlob(capture string, item capturedBlob) ([]byte, error) {
	if !hexLength(item.SHA256, 64) {
		return nil, errors.New("invalid capture blob digest")
	}

	f, err := os.Open(filepath.Join(capture, "blobs", item.SHA256+".gz")) //nolint:gosec // G304: the digest is validated above and cannot contain path separators.
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	reader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	defer func() { _ = reader.Close() }()

	// A captured string may contain one million four-byte Unicode characters.
	data, err := io.ReadAll(io.LimitReader(reader, 4<<20+1))
	if err != nil {
		return nil, err
	}

	if len(data) != item.Bytes || digest(data) != item.SHA256 {
		return nil, errors.New("blob digest mismatch")
	}

	return data, nil
}

func indexSuiteTests(ctx context.Context, capture string, observations map[string]capturedObservation, index replayIndex) ([]object, object, error) {
	var collection struct{ Tests []object }
	if err := readJSON(filepath.Join(capture, "collection.json"), &collection); err != nil {
		return nil, nil, err
	}

	statuses := map[string][]object{}

	if err := readJSONLines(ctx, filepath.Join(capture, "test-status.jsonl"), func(row object) error {
		key := text(row["test"])
		statuses[key] = append(statuses[key], row)

		return nil
	}); err != nil {
		return nil, nil, err
	}

	indexed := map[string][]string{}

	for _, id := range sortedKeys(observations) {
		o := observations[id]
		indexed[o.Test] = append(indexed[o.Test], id)
	}

	outcomes, reasons := map[string]int{}, map[string]int{}
	withObservations := 0

	for _, test := range collection.Tests {
		key := text(test["test"])
		phases := statuses[key]
		outcome := suiteTestOutcome(phases)

		ids := indexed[key]
		if ids == nil {
			ids = []string{}
		}

		test["outcome"], test["observations"], test["phases"] = outcome, ids, phases
		test["scope"] = "no_raw_file_analyzer_boundary"

		if len(ids) > 0 {
			withObservations++
			test["scope"] = "captured_analyzer_boundary"
		}

		outcomes[outcome]++
	}

	for _, excluded := range index.Excluded {
		reasons[text(excluded["reason"])]++
	}

	counts := object{
		"collected_tests":         len(collection.Tests),
		"observations":            len(observations),
		"unique_inputs":           len(index.Groups),
		"tests_with_observations": withObservations,
		"excluded_observations":   len(index.Excluded),
		"outcomes":                outcomes,
		"excluded_reasons":        reasons,
	}

	return collection.Tests, counts, nil
}

func suiteFamily(rule string) string {
	if mapped := suiteFamilies[rule]; mapped != "" {
		return mapped
	}

	if strings.HasPrefix(rule, "NV-") || strings.HasPrefix(rule, "PY-") {
		return rule[3:]
	}

	return rule
}

func boundaryKind(function string) string {
	switch function {
	case "node", "analyze", "analyze_dependency_sources", "posture_findings", "_analyze_python":
		return "public_or_direct_analyzer"
	default:
		return "internal_component"
	}
}

func compareSuite(ctx context.Context, capture, replay, results, output string, w io.Writer) error {
	var index replayIndex
	if err := readJSON(filepath.Join(replay, "index.json"), &index); err != nil {
		return err
	}

	groups := map[string]replayGroup{}
	for _, g := range index.Groups {
		if _, exists := groups[g.ID]; exists {
			return errors.New("duplicate replay group")
		}

		groups[g.ID] = g
	}

	observations := map[string]capturedObservation{}

	if err := readJSONLines(ctx, filepath.Join(capture, "observations.jsonl"), func(o capturedObservation) error {
		if _, exists := observations[o.ID]; exists {
			return errors.New("duplicate observation")
		}

		observations[o.ID] = o

		return nil
	}); err != nil {
		return err
	}

	comparison := suiteReplayComparison{
		groups:       groups,
		observations: observations,
		seen:         map[string]bool{},
		summary:      newSuiteComparison(),
	}

	err := readJSONLines(ctx, results, comparison.add)
	if err != nil {
		return err
	}

	summary, seen := comparison.summary, comparison.seen

	if len(seen) != len(groups) {
		return fmt.Errorf("incomplete replay: %d of %d", len(seen), len(groups))
	}

	summary.ScannedInputs, summary.DifferingObservations = len(seen), len(summary.Differences)
	if err = writeJSON(output, summary); err != nil {
		return err
	}

	return printJSON(w, object{
		"scanned_inputs":                  summary.ScannedInputs,
		"differing_observations":          summary.DifferingObservations,
		"missing_observation_counts":      summary.Missing,
		"extra_observation_counts":        summary.Extra,
		"positive_observation_counts":     summary.Positive,
		"public_or_direct_missing_counts": summary.PrimaryMissing,
		"public_or_direct_extra_counts":   summary.PrimaryExtra,
		"replay_errors":                   summary.Errors,
		"decisions":                       summary.Decisions,
		"coverage":                        summary.Coverage,
	})
}

func compareObservation(o capturedObservation, r replayResult) replayDifference {
	found, wanted := map[string]bool{}, map[string]bool{}
	for _, f := range r.Findings {
		found[suiteFamily(f.RuleID)] = true
	}

	for _, f := range o.UpstreamFindings {
		wanted[f.Rule] = true
	}

	familyFound := map[string]bool{}

	for _, family := range o.Families {
		if found[family] {
			familyFound[family] = true
		}
	}

	row := replayDifference{
		Observation:  o.ID,
		Test:         o.Test,
		Input:        r.ID,
		Module:       o.Module,
		Function:     o.Function,
		Missing:      difference(wanted, found),
		Extra:        difference(familyFound, wanted),
		Wanted:       sortedKeys(wanted),
		Found:        sortedKeys(found),
		Files:        o.Files,
		ContextFlags: o.ContextFlags,
		BoundaryKind: boundaryKind(o.Function),
		Coverage:     string(r.Coverage),
		Diagnostics:  r.Diagnostics,
	}
	if r.Error != "" {
		value := r.Error
		row.Error = &value
	}

	return row
}

func countDifferences(summary *suiteComparison, row replayDifference) {
	for _, key := range row.Wanted {
		summary.Positive[key]++
	}

	for _, key := range row.Missing {
		summary.Missing[key]++
		if row.BoundaryKind == "public_or_direct_analyzer" {
			summary.PrimaryMissing[key]++
		}
	}

	for _, key := range row.Extra {
		summary.Extra[key]++
		if row.BoundaryKind == "public_or_direct_analyzer" {
			summary.PrimaryExtra[key]++
		}
	}
}

// captureCanonical preserves the original capture ID format: sorted keys,
// ASCII JSON strings, and spaces after commas and colons.
func captureCanonical(value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var v any
	if err = json.Unmarshal(b, &v); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	if err = writeCanonical(&out, v); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		return writeCanonicalObject(out, x)

	case []any:
		out.WriteByte('[')

		for i, item := range x {
			if i > 0 {
				out.WriteString(", ")
			}

			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}

		out.WriteByte(']')
	case string:
		writeASCIIString(out, x)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}

		out.Write(b)
	}

	return nil
}

func writeASCIIString(out *bytes.Buffer, s string) {
	out.WriteByte('"')

	for _, r := range s {
		if escaped := asciiEscapes[r]; escaped != "" {
			out.WriteString(escaped)
		} else if r < 0x20 || r > 0x7e {
			writeASCIIUnicode(out, r)
		} else {
			out.WriteRune(r)
		}
	}

	out.WriteByte('"')
}

func (b *suitePreparation) add(o capturedObservation) error {
	if o.ID == "" {
		return errors.New("capture observation is missing an ID")
	}

	if _, exists := b.observations[o.ID]; exists {
		return errors.New("duplicate capture observation")
	}

	b.observations[o.ID] = o

	reason := replayExclusion(o.Files)
	if reason != "" {
		b.index.Excluded = append(b.index.Excluded, object{"observation": o.ID, "test": o.Test, "reason": reason})
		return nil
	}

	canonical, err := captureCanonical(o.Files)
	if err != nil {
		return err
	}

	key := digest(canonical)

	position, exists := b.positions[key]
	if !exists {
		position = len(b.index.Groups)
		b.positions[key] = position
		b.index.Groups = append(b.index.Groups, replayGroup{ID: key, Files: o.Files, Observations: []string{}})
	}

	b.index.Groups[position].Observations = append(b.index.Groups[position].Observations, o.ID)

	return nil
}

func replayFileExclusion(name string, item capturedBlob) string {
	if !replayArtifactPath(name) {
		return "path_not_a_scout_artifact_path"
	}

	if item.SHA256 == "" {
		if item.Omitted != "" {
			return item.Omitted
		}

		return "no_bytes"
	}

	if !hexLength(item.SHA256, 64) {
		return "invalid_blob_digest"
	}

	if item.Representation == "python_surrogate_string" {
		return "not_a_utf8_file_python_surrogate_string"
	}

	if item.Bytes < 0 || item.Bytes > 4<<20 {
		return "replay_input_limit"
	}

	return ""
}

func replayArtifactPath(name string) bool {
	parts := strings.Split(name, "/")
	return name != "" && !strings.HasPrefix(name, "/") && !strings.ContainsAny(name, "\\\x00") && !slices.Contains(parts, "..") && len(name) <= 1024 && len(parts) <= 32
}

func newSuiteComparison() suiteComparison {
	return suiteComparison{
		Missing:        map[string]int{},
		Extra:          map[string]int{},
		Positive:       map[string]int{},
		PrimaryMissing: map[string]int{},
		PrimaryExtra:   map[string]int{},
		Errors:         map[string]int{},
		Decisions:      map[string]int{},
		Coverage:       map[string]int{},
		Differences:    []replayDifference{},
	}
}

func (c *suiteReplayComparison) add(result replayResult) error {
	if err := replaywire.ValidateComparison(result); err != nil {
		return err
	}

	group, exists := c.groups[result.ID]
	if c.seen[result.ID] || !exists {
		return errors.New("duplicate or unknown replay result")
	}

	c.seen[result.ID] = true
	if result.Error != "" {
		c.summary.Errors[result.Error]++
	}

	c.summary.Decisions[string(result.Decision)]++
	c.summary.Coverage[string(result.Coverage)]++

	for _, id := range group.Observations {
		if err := c.addObservation(id, result); err != nil {
			return err
		}
	}

	return nil
}

func (c *suiteReplayComparison) addObservation(id string, result replayResult) error {
	o, exists := c.observations[id]
	if !exists {
		return errors.New("replay refers to an unknown observation")
	}

	row := compareObservation(o, result)
	countDifferences(&c.summary, row)

	if len(row.Missing) > 0 || len(row.Extra) > 0 || row.Error != nil {
		c.summary.Differences = append(c.summary.Differences, row)
	}

	return nil
}

func writeCanonicalObject(out *bytes.Buffer, x map[string]any) error {
	out.WriteByte('{')

	for i, key := range sortedKeys(x) {
		if i > 0 {
			out.WriteString(", ")
		}

		writeASCIIString(out, key)
		out.WriteString(": ")

		if err := writeCanonical(out, x[key]); err != nil {
			return err
		}
	}

	out.WriteByte('}')

	return nil
}

func writeASCIIUnicode(out *bytes.Buffer, r rune) {
	if r > 0xffff {
		high, low := utf16.EncodeRune(r)
		_, _ = fmt.Fprintf(out, `\u%04x\u%04x`, high, low)
	} else {
		_, _ = fmt.Fprintf(out, `\u%04x`, r)
	}
}

func suiteTestOutcome(phases []object) string {
	outcome := "passed"

	for _, p := range phases {
		if value := text(p["outcome"]); value != "passed" {
			outcome = value
			break
		}
	}

	return outcome
}

func writeSuiteIndex(output string, index replayIndex, tests []object, counts object) error {
	for name, value := range map[string]any{"index.json": index, "test-index.json": tests, "counts.json": counts} {
		if err := writeJSON(filepath.Join(output, name), value); err != nil {
			return err
		}
	}

	return nil
}
