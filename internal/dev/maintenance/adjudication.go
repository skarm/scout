package maintenance

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/dev/replaywire"
	"github.com/skarm/scout/internal/syntax/frontend"
)

//go:embed data/adjudication.json
var adjudicationData []byte

type testSite struct {
	Test   string `json:"test"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	SHA256 string `json:"sha256"`
}
type fileIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type adjudicator struct {
	old, current map[string]replayDifference
	results      map[string]replayResult
	rules        map[string]string
	reasons      object
	sites        []testSite
	siteIDs      map[string]int
	cachedSites  map[string]testSite
	inputs       []string
	inputIDs     map[string]int
	counts       map[string]int
	rows         [][]any
	upstream     string
}

func adjudicateUpstreamSuite(ctx context.Context, o options, w io.Writer) error {
	if err := o.require("before", "after", "results", "upstream", "output"); err != nil {
		return err
	}

	a, after, err := newAdjudicator(ctx, o)
	if err != nil {
		return err
	}

	if err := a.addAllObservations(ctx); err != nil {
		return err
	}

	runtimeFiles, err := ScannerRuntimeFiles(ctx, o.root)
	if err != nil {
		return err
	}

	identities, err := runtimeIdentities(o.root, runtimeFiles)
	if err != nil {
		return err
	}

	out, err := a.document(o, after, identities)
	if err != nil {
		return err
	}

	if err = writeJSON(o.get("output"), out); err != nil {
		return err
	}

	delete(out, "rows")
	delete(out, "test_sites")
	delete(out, "inputs")
	delete(out, "reasons")
	delete(out, "runtime_files")

	return printJSON(w, out)
}

func newAdjudicator(ctx context.Context, o options) (*adjudicator, suiteComparison, error) {
	var before, after suiteComparison
	if err := readJSON(o.get("before"), &before); err != nil {
		return nil, after, err
	}

	if err := readJSON(o.get("after"), &after); err != nil {
		return nil, after, err
	}

	a := &adjudicator{
		old:         map[string]replayDifference{},
		current:     map[string]replayDifference{},
		results:     map[string]replayResult{},
		rules:       policyRules(),
		siteIDs:     map[string]int{},
		cachedSites: map[string]testSite{},
		inputIDs:    map[string]int{},
		counts:      map[string]int{},
		rows:        [][]any{},
		sites:       []testSite{},
		inputs:      []string{},
		upstream:    o.get("upstream"),
	}

	var err error

	a.old, err = indexAdjudicationDifferences(before.Differences, "previous")
	if err != nil {
		return nil, after, err
	}

	a.current, err = indexAdjudicationDifferences(after.Differences, "current")
	if err != nil {
		return nil, after, err
	}

	err = readJSONLines(ctx, o.get("results"), a.addResult)
	if err != nil {
		return nil, after, err
	}

	if len(a.results) != after.ScannedInputs {
		return nil, after, errors.New("missing replay results")
	}

	if err := a.loadMetadata(o.root); err != nil {
		return nil, after, err
	}

	return a, after, nil
}

func validAdjudicationResult(r replayResult) error {
	if err := r.Validate(scout.Version()); err != nil {
		return err
	}

	if r.Error != "" && !replaywire.InputRefusal(r.Error) {
		return errors.New("resource/runtime errors must be retried before adjudication")
	}

	return nil
}

func policyRules() map[string]string {
	policies := map[string]string{ //nolint:gosec // G101: public rule-family names, not credential values.
		"python":          "AST1 AST2 AST3 AST4 AST5 AST6 AST7 AST8 AST9 AST10 TT1 TT2 TT3 TT4 TT5 TT6",
		"shell_truth":     "TM1 TM2 TM3 TM4",
		"credential":      "PE1 PE2 PE3 PE4 PE5",
		"network":         "E1 E2 E3 E4 E5 SSRF1 SSRF2 SSRF3",
		"prompt":          "P1 P2 P3 P4 P5 P6 P7 P8 P9",
		"agency":          "EA1 EA2 EA3 EA4 EA5",
		"output":          "OH1 OH2 OH3",
		"memory":          "MP1 MP2 MP3",
		"agent":           "RA1 RA2 RA3 AS1 AS2 AS3 AR1 AR2 AR3",
		"supply":          "SC1 SC2 SC3 SC5 SC6 SC7 SC8 SC9 SC10",
		"integrity":       "AE1 AE2 AE3 AE4 AE5 AE6",
		"hooks":           "BH1 BH2 BH3",
		"permissions":     "LP1 LP2 LP3 LP4",
		"updates":         "RP1 RP2 RP3",
		"tools":           "TP1 TP2 TP3 TP4",
		"triggers":        "TR1 TR2 TR3",
		"deserialization": "DS1 DS2 DS3 DS4",
		"yara":            "YR1 YR2 YR3 YR4",
		"offline_service": "SC4",
	}
	out := map[string]string{}

	for key, rules := range policies {
		for rule := range strings.FieldsSeq(rules) {
			out[rule] = key
		}
	}

	return out
}

func (a *adjudicator) addObservation(ctx context.Context, id string) error {
	prior, hadPrior := a.old[id]
	current, hasCurrent := a.current[id]

	row := current
	if !hasCurrent {
		row = prior
	}

	result, exists := a.results[row.Input]
	if !exists {
		return errors.New("observation has no replay result")
	}

	siteID, err := a.observationSite(ctx, row.Test)
	if err != nil {
		return err
	}

	inputID := a.internInput(row.Input)

	decisions, err := a.deltaDecisions(row, prior, current, result)
	if err != nil {
		return err
	}

	if len(decisions) == 0 {
		reason := "resolved"
		if result.Error != "" {
			reason = "refused"
		}

		decisions = append(decisions, []string{"input", "replay", reason})
		a.counts[reason]++
	}

	diagnostics := slices.Clone(result.Diagnostics)
	if diagnostics == nil {
		diagnostics = []string{}
	}

	slices.Sort(diagnostics)

	var resultError any
	if result.Error != "" {
		resultError = result.Error
	}

	a.rows = append(a.rows, []any{id, siteID, inputID, row.Module, row.Function, nonNil(prior.Missing), nonNil(prior.Extra), nonNil(current.Missing), nonNil(current.Extra), result.Coverage, result.Decision, diagnostics, decisions, hadPrior, resultError})

	return nil
}

func (a *adjudicator) deltaDecisions(row, prior, current replayDifference, result replayResult) ([][]string, error) {
	out := make([][]string, 0)

	for _, direction := range []string{"missing", "extra"} {
		before, now := prior.Missing, current.Missing
		if direction == "extra" {
			before, now = prior.Extra, current.Extra
		}

		all := stringSet(append(slices.Clone(before), now...))
		present := stringSet(now)

		for _, rule := range sortedKeys(all) {
			policy, exists := a.rules[rule]
			if !exists {
				return nil, fmt.Errorf("unreviewed rule policy: %s", rule)
			}

			reason := deltaReason(row, result, direction, rule, present[rule], policy)
			if a.reasons[reason] == nil {
				return nil, errors.New("compatibility reason is missing")
			}

			a.counts[reason]++
			out = append(out, []string{direction, rule, reason})
		}
	}

	return out, nil
}

func (a *adjudicator) locateTest(ctx context.Context, name string) (testSite, error) {
	parts := strings.Split(name, "::")

	source, err := safeJoin(a.upstream, parts[0])
	if err != nil {
		return testSite{}, err
	}

	data, err := os.ReadFile(source) //nolint:gosec // G304: safeJoin bounds the pinned upstream test path to the selected source tree.
	if err != nil {
		return testSite{}, err
	}

	sha := digest(data)
	if site, exists := a.cachedSites[name]; exists && site.SHA256 == sha {
		return site, nil
	}

	opts := frontend.DefaultOptions()
	opts.Python = true

	parsed, err := frontend.Parse(ctx, opts, "python", string(data))
	if err != nil {
		return testSite{}, fmt.Errorf("test source location requires the native parser or a verified cached site: %w", err)
	}

	starts := make([]int, 0)
	findPythonDefinition(parsed.AST, nil, parts[1:], &starts)

	if len(starts) != 1 {
		return testSite{}, fmt.Errorf("test source location unavailable: %s", name)
	}

	return testSite{Test: name, File: parts[0], Line: strings.Count(string(data[:starts[0]]), "\n") + 1, SHA256: sha}, nil
}

func (a *adjudicator) document(o options, after suiteComparison, files []fileIdentity) (object, error) {
	beforeSHA, err := fileDigest(o.get("before"))
	if err != nil {
		return nil, err
	}

	afterSHA, err := fileDigest(o.get("after"))
	if err != nil {
		return nil, err
	}

	resultsSHA, err := fileDigest(o.get("results"))
	if err != nil {
		return nil, err
	}

	var data object
	if err = decodeJSON(adjudicationData, &data); err != nil {
		return nil, err
	}

	out := object{
		"schema_version":      1,
		"upstream_commit":     upstreamCommit,
		"scout_version":       scout.Version(),
		"runtime_files":       files,
		"scope":               "Explicit contract/family compatibility decisions, not manual review of every Python assertion, verdict equivalence or detector-quality measurement. Accepted limitations remain limitations.",
		"before_sha256":       beforeSHA,
		"after_sha256":        afterSHA,
		"results_sha256":      resultsSHA,
		"before_observations": len(a.old),
		"after_observations":  len(a.current),
		"union_observations":  len(a.rows),
		"before_ids_sha256":   digest([]byte(strings.Join(sortedKeys(a.old), "\n") + "\n")),
		"scanned_inputs":      len(a.results),
		"unclassified_deltas": 0,
		"reason_counts":       a.counts,
		"row_columns":         data["row_columns"],
		"decision_columns":    []string{"direction", "rule", "reason"},
		"reasons":             a.reasons,
		"test_sites":          a.sites,
		"inputs":              a.inputs,
		"rows":                a.rows,
	}
	if after.ScannedInputs != len(a.results) {
		return nil, errors.New("replay coverage changed during adjudication")
	}

	return out, nil
}

func (a *adjudicator) addAllObservations(ctx context.Context) error {
	ids := map[string]bool{}
	for id := range a.old {
		ids[id] = true
	}

	for id := range a.current {
		ids[id] = true
	}

	for _, id := range sortedKeys(ids) {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := a.addObservation(ctx, id); err != nil {
			return err
		}
	}

	return nil
}

func (a *adjudicator) addResult(r replayResult) error {
	if err := validAdjudicationResult(r); err != nil {
		return err
	}

	if _, exists := a.results[r.ID]; exists {
		return errors.New("duplicate result")
	}

	a.results[r.ID] = r

	return nil
}

func (a *adjudicator) observationSite(ctx context.Context, test string) (int, error) {
	base, _, _ := strings.Cut(test, "[")

	siteID, exists := a.siteIDs[base]
	if !exists {
		site, err := a.locateTest(ctx, base)
		if err != nil {
			return 0, err
		}

		siteID = len(a.sites)
		a.siteIDs[base] = siteID
		a.sites = append(a.sites, site)
	}

	return siteID, nil
}

func (a *adjudicator) loadMetadata(root string) error {
	var data struct{ Reasons object }
	if err := decodeJSON(adjudicationData, &data); err != nil {
		return err
	}

	a.reasons = data.Reasons

	var previous struct {
		Sites []testSite `json:"test_sites"`
	}
	if err := readJSON(filepath.Join(root, "testdata/provenance/upstream-adjudication-0.22.json"), &previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	for _, site := range previous.Sites {
		a.cachedSites[site.Test] = site
	}

	return nil
}

func (a *adjudicator) internInput(input string) int {
	inputID, exists := a.inputIDs[input]
	if !exists {
		inputID = len(a.inputs)
		a.inputIDs[input] = inputID
		a.inputs = append(a.inputs, input)
	}

	return inputID
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}

	return v
}

func deltaReason(row replayDifference, r replayResult, direction, rule string, present bool, policy string) string {
	if !present {
		return "resolved"
	}

	if r.Error != "" {
		return "refused"
	}

	if !slices.Contains([]string{"node", "analyze", "analyze_dependency_sources"}, row.Function) {
		return "component"
	}

	if direction != "missing" {
		return policy
	}

	return missingDeltaReason(row, r, rule, policy)
}

func missingDeltaReason(row replayDifference, r replayResult, rule, policy string) string {
	if rule == "SC2" && knownShellGap(row.Input) {
		return "known_gap"
	}

	if len(row.Files) == 1 && hasCounterpart(row, r, rule) {
		return "taxonomy"
	}

	if slices.Contains(row.ContextFlags, "file_type:python") && !hasPythonFilename(row.Files) {
		return "type_context"
	}

	return policy
}

func knownShellGap(id string) bool {
	switch id {
	case "89270abdb8a5d12c004cc1ee1af6045a4505ccf5aaf005ef402c8d98f791a5aa", "436d27bf9b4bae79293dd0c35041a4a568491b655cdd61f5af411be65cc32ea8", "21df57ef92173add9d1b46c96b6a9574e93800c27a9e18c298bb4fdc52043539", "18b1b9334883f45967a2eb747fa6b742043bdcdd7e6caf0bdc212294cdf5b0cf":
		return true
	}

	return false
}

func hasCounterpart(row replayDifference, result replayResult, rule string) bool {
	counterparts := map[string]string{
		"LP1": "LP3",
		"LP4": "LP2",
		"RP1": "SC001 AG001 SC7M",
		"PE3": "FS001 SH003",
		"SC9": "BI001 AE3",
		"AE2": "AR001 AR002 AE3",
		"AE4": "BI001 AE3",
		"AE5": "BI001 AE3",
		"AE6": "AE4 P1 P2",
		"TT1": "TT2 TT5",
		"TT2": "TT1",
		"TT3": "TT4",
		"TT4": "TT3",
		"TT6": "AST10",
		"P4":  "AR1 AR2",
		"E4":  "P3 DE001",
		"SC2": "SC3 SC001",
		"SC3": "SC2 SC001",
	}
	candidates := strings.Fields(counterparts[rule])

	for _, finding := range result.Findings {
		_, exists := row.Files[finding.Location.Path]
		if exists && slices.Contains(candidates, suiteFamily(finding.RuleID)) {
			return true
		}
	}

	return false
}

func hasPythonFilename(files map[string]capturedBlob) bool {
	for name := range files {
		if slices.Contains([]string{".py", ".pyw", ".pyi"}, strings.ToLower(filepath.Ext(name))) {
			return true
		}
	}

	return false
}

func findPythonDefinition(node *frontend.Node, scope, target []string, starts *[]int) {
	if node == nil {
		return
	}

	next := scope

	if kind := node.Kind(); kind == frontend.ClassDef || kind == frontend.FunctionDef || kind == frontend.AsyncFunctionDef {
		next = append(slices.Clone(scope), node.String(frontend.FieldName))
		if slices.Equal(next, target) {
			*starts = append(*starts, node.Start)
		}
	}

	for _, child := range node.Children() {
		findPythonDefinition(child, next, target, starts)
	}
}

func runtimeIdentities(root string, runtimeFiles []string) ([]fileIdentity, error) {
	identities := make([]fileIdentity, 0, len(runtimeFiles))
	for _, path := range runtimeFiles {
		sha, err := fileDigest(path)
		if err != nil {
			return nil, err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}

		identities = append(identities, fileIdentity{Path: filepath.ToSlash(rel), SHA256: sha})
	}

	return identities, nil
}

func indexAdjudicationDifferences(rows []replayDifference, label string) (map[string]replayDifference, error) {
	indexed := map[string]replayDifference{}
	for _, row := range rows {
		if _, exists := indexed[row.Observation]; exists {
			return nil, fmt.Errorf("duplicate %s observation", label)
		}

		indexed[row.Observation] = row
	}

	return indexed, nil
}
