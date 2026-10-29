package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	scanreport "github.com/skarm/scout/report"
)

type preparedCase struct {
	Spec                   object
	Argument, Root, SHA256 string
	Files                  []inventoryFile
}

type comparisonSession struct {
	root, upstream, scanner, scoutBinary, output string
}

type comparisonEnvironment struct {
	home, profile string
	env           []string
}

type comparisonResults struct {
	rows         []object
	schemaErrors int
	rejections   []string
}

type comparisonPreparation struct {
	coverage     object
	cases        []preparedCase
	exported     []object
	packageRoots map[string]bool
}

func compareUpstream(ctx context.Context, o options, w io.Writer) error {
	session, err := selectComparison(o)
	if err != nil {
		return err
	}

	source, installed, err := session.verifyRuntime(ctx)
	if err != nil {
		return err
	}

	environment, err := session.prepareFilesystem(ctx)
	if err != nil {
		return err
	}

	if err := session.writeEnvironment(source, installed); err != nil {
		return err
	}

	cases, err := prepareComparison(session.root, session.output, session.upstream, source)
	if err != nil {
		return err
	}

	results := comparisonResults{rows: []object{}, rejections: []string{}}

	for _, tc := range cases {
		row, err := runComparisonCase(ctx, session.output, environment.home, environment.profile, environment.env, session.scanner, session.scoutBinary, tc)
		if err != nil {
			return err
		}

		if err := results.add(tc, row, len(cases), w); err != nil {
			return err
		}
	}

	return results.finish(session.output, len(cases))
}

func selectComparison(o options) (*comparisonSession, error) {
	if err := o.require("upstream-source", "skillspector", "scout", "output"); err != nil {
		return nil, err
	}

	if err := requireSandbox(); err != nil {
		return nil, err
	}

	session := &comparisonSession{root: o.root}
	for _, field := range []struct {
		name        string
		destination *string
	}{{name: "upstream-source", destination: &session.upstream}, {name: "skillspector", destination: &session.scanner}, {
		name:        "scout",
		destination: &session.scoutBinary,
	}, {
		name:        "output",
		destination: &session.output,
	}} {
		value, err := filepath.Abs(o.get(field.name))
		if err != nil {
			return nil, err
		}

		*field.destination = value
	}

	return session, nil
}

func (s *comparisonSession) verifyRuntime(ctx context.Context) (sourceInventory, externalRuntime, error) {
	source, err := verifyUpstream(s.root, s.upstream)
	if err != nil {
		return sourceInventory{}, externalRuntime{}, err
	}
	// Only this explicitly selected developer oracle needs the pinned Python venv.
	installed, err := verifyInstalledRuntime(ctx, filepath.Join(filepath.Dir(s.scanner), "python"), s.upstream)

	return source, installed, err
}

func (s *comparisonSession) prepareFilesystem(ctx context.Context) (comparisonEnvironment, error) {
	if err := newOutput(s.output); err != nil {
		return comparisonEnvironment{}, err
	}

	environment := comparisonEnvironment{home: filepath.Join(s.output, "home")}

	tmp := filepath.Join(s.output, "tmp")
	for _, dir := range []string{environment.home, tmp, filepath.Join(s.output, "reports")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return comparisonEnvironment{}, err
		}
	}

	environment.profile = networkProfile(s.output, false)
	environment.env = append(cleanEnvironment(s.scanner, environment.home, tmp), "SKILLSPECTOR_OSV_TIMEOUT=0", "SKILLSPECTOR_MAX_WORKFLOW_SECONDS=45")

	return environment, checkNetworkDenial(ctx, environment.profile, environment.home, environment.env)
}

func (s *comparisonSession) writeEnvironment(source sourceInventory, installed externalRuntime) error {
	info, err := asObject(installed)
	if err != nil {
		return err
	}

	sha, err := fileDigest(s.scoutBinary)
	if err != nil {
		return err
	}

	info["executed_at"], info["source_commit"], info["source_inventory_files"] = time.Now().UTC().Format(time.RFC3339Nano), upstreamCommit, source.FileCount
	info["scout_binary_sha256"], info["network"] = sha, "OS deny network* verified"
	info["scout_command"], info["upstream_command"] = []string{"scan", "--profile", "standard", "--timeout", "45s", "--format", "json", "--"}, []string{"scan", "--format", "json", "--no-llm"}

	return writeJSON(filepath.Join(s.output, "environment.json"), info)
}

func (r *comparisonResults) add(tc preparedCase, row object, total int, w io.Writer) error {
	r.rows = append(r.rows, row)

	r.schemaErrors += comparisonErrorCount(row)
	if boolean(at(row, "upstream", "expected_rejection")) {
		r.rejections = append(r.rejections, text(tc.Spec["id"]))
	}

	_, err := fmt.Fprintf(w, "%d / %d %s\n", len(r.rows), total, text(tc.Spec["id"]))

	return err
}

func (r *comparisonResults) finish(output string, total int) error {
	slices.SortFunc(r.rows, func(a, b object) int { return strings.Compare(text(a["id"]), text(b["id"])) })

	report := object{
		"schema_version":               1,
		"source_commit":                upstreamCommit,
		"normalization":                comparisonAliases(),
		"scope":                        "Static same-byte packages; family+file sets, raw IDs/lines/severity retained. No score, coverage, verdict or semantic-equivalence claim.",
		"case_count":                   total,
		"execution_or_schema_errors":   r.schemaErrors,
		"expected_upstream_rejections": r.rejections,
		"cases":                        r.rows,
	}
	if err := writeJSON(filepath.Join(output, "comparison.json"), report); err != nil {
		return err
	}

	if r.schemaErrors != 0 {
		return fmt.Errorf("comparison completed with %d execution or schema errors", r.schemaErrors)
	}

	return nil
}

func comparisonErrorCount(row object) int {
	count := 0

	for _, kind := range []string{"upstream", "scout"} {
		if at(row, kind, errorKey) != nil {
			count++
		}
	}

	return count
}

func prepareComparison(root, output, upstream string, pinned sourceInventory) ([]preparedCase, error) {
	var spec object
	if err := readJSON(filepath.Join(root, "testdata/differential/cases.json"), &spec); err != nil {
		return nil, err
	}

	coverage, err := comparisonCorpusCoverage(spec, pinned)
	if err != nil {
		return nil, err
	}

	preparation := comparisonPreparation{
		coverage:     coverage,
		cases:        []preparedCase{},
		exported:     []object{},
		packageRoots: map[string]bool{},
	}
	for _, value := range array(spec["cases"]) {
		if err := preparation.add(root, output, upstream, obj(value)); err != nil {
			return nil, err
		}
	}

	cases, exported, packageRoots := preparation.cases, preparation.exported, preparation.packageRoots

	if err := validateComparisonCoverage(coverage, packageRoots); err != nil {
		return nil, err
	}

	if err := writeJSON(filepath.Join(output, "fixture-coverage.json"), object{
		"source_commit": upstreamCommit,
		"files":         coverage,
		"uncovered":     []string{},
	}); err != nil {
		return nil, err
	}

	if err := writeJSON(filepath.Join(output, "corpus.json"), object{"schema_version": 1, "cases": exported}); err != nil {
		return nil, err
	}

	return cases, nil
}

func lenStringValues(v any) int {
	if values, ok := v.([]string); ok {
		return len(values)
	}

	return len(array(v))
}

func prepareComparisonCase(root, output, upstream string, spec object) (preparedCase, error) {
	tc := preparedCase{Spec: spec}

	id := text(spec["id"])
	if id == "" {
		return tc, errors.New("case ID missing")
	}

	target, err := safeJoin(filepath.Join(output, "packages"), id)
	if err != nil {
		return tc, err
	}

	if err = os.MkdirAll(target, 0o700); err != nil {
		return tc, err
	}

	source := obj(spec["source"])

	kind, name := text(source["kind"]), text(source["path"])
	if err := materializeComparisonSource(root, upstream, target, source); err != nil {
		return tc, err
	}

	tc.Root = target

	tc.Argument, err = comparisonArgument(target, spec, kind, name)
	if err != nil {
		return tc, err
	}

	tc.Files, err = treeInventory(target)
	if err != nil {
		return tc, err
	}

	canonical, err := compactCanonical(tc.Files)
	if err != nil {
		return tc, err
	}

	tc.SHA256 = digest(canonical)

	return tc, nil
}

func writeAuthoredFiles(target string, files object) error {
	for file, content := range files {
		destination, err := safeJoin(target, file)
		if err != nil {
			return err
		}

		if err = os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}

		if err = os.WriteFile(destination, []byte(text(content)), 0o600); err != nil {
			return err
		}
	}

	return nil
}

func compactCanonical(value any) ([]byte, error) {
	data, err := captureCanonical(value)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer

	err = json.Compact(&out, data)

	return out.Bytes(), err
}

func recordFixtureCoverage(coverage object, tc preparedCase) error {
	source := obj(tc.Spec["source"])

	kind, name := text(source["kind"]), text(source["path"])
	if !strings.HasPrefix(kind, "upstream_fixture") {
		return nil
	}

	for _, file := range tc.Files {
		original := name
		if kind != "upstream_fixture_file" {
			original += "/" + file.Path
		}

		entry, err := comparisonCoverageEntry(coverage, original, file)
		if err != nil {
			return err
		}

		if mode := text(tc.Spec["mode"]); mode != "" && mode != "static" {
			continue
		}

		key := "package_cases"
		if kind == "upstream_fixture_file" {
			key = "file_cases"
		}

		values, ok := entry[key].([]string)
		if !ok {
			return errors.New("invalid fixture coverage list")
		}

		entry[key] = append(values, text(tc.Spec["id"]))
	}

	return nil
}

func comparisonCommand(kind, mode, scanner, scoutBinary, argument string) []string {
	args := []string{scanner, "scan", "--format", "json", "--no-llm"}
	if kind == "scout" {
		args = []string{scoutBinary, "scan", "--profile", "standard", "--timeout", "45s", "--format", "json", "--"}
	} else if mode == "mcp_registry" {
		args = append(args, "--mcp-registry")
	}

	return append(args, argument)
}

func runComparisonCase(ctx context.Context, output, home, profile string, env []string, scanner, scoutBinary string, tc preparedCase) (object, error) {
	mode := text(tc.Spec["mode"])
	if mode == "" {
		mode = "static"
	}

	row := object{"id": text(tc.Spec["id"]), "mode": mode, "input_sha256": tc.SHA256}
	for _, kind := range []string{"upstream", "scout"} {
		observed, err := runComparisonRuntime(ctx, output, home, profile, env, comparisonCommand(kind, mode, scanner, scoutBinary, tc.Argument), kind, tc)
		if err != nil {
			return nil, err
		}

		row[kind] = observed
	}

	return finalizeComparisonCase(row, tc)
}

func runComparisonRuntime(ctx context.Context, output, home, profile string, env, args []string, kind string, tc preparedCase) (object, error) {
	result, err := runSandboxed(ctx, profile, home, env, args...)
	if err != nil {
		return nil, err
	}

	if err := writeComparisonStreams(output, text(tc.Spec["id"]), kind, result); err != nil {
		return nil, err
	}

	return comparisonObservation(tc.Spec, kind, result), nil
}

func writeComparisonStreams(output, id, kind string, result processResult) error {
	for suffix, data := range map[string][]byte{"json": result.Stdout, "stderr": result.Stderr} {
		if err := os.WriteFile(filepath.Join(output, "reports", id+"."+kind+"."+suffix), data, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func comparisonObservation(spec object, kind string, result processResult) object {
	normalized, err := normalizeComparisonResult(spec, kind, result)
	if err != nil {
		normalized = object{errorKey: err.Error()}
	}

	normalized["exit_code"], normalized["seconds"], normalized["report_sha256"] = result.Code, result.Seconds, digest(result.Stdout)

	return normalized
}

func finalizeComparisonCase(row object, tc preparedCase) (object, error) {
	current, err := treeInventory(tc.Root)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(current, tc.Files) {
		return nil, errors.New("package changed during scanning")
	}

	if at(row, "upstream", errorKey) == nil && at(row, "scout", errorKey) == nil {
		addComparisonDifferences(row)
	}

	return row, nil
}

func normalizeComparisonResult(spec object, kind string, result processResult) (object, error) {
	if expectedUpstreamRejection(spec, kind, result) {
		return object{
			findingsKey:            []any{},
			coverageKey:            "rejected_invalid_registry",
			"execution_successful": false,
			"expected_rejection":   true,
		}, nil
	}

	if kind == "upstream" {
		// The upstream CLI has its own historical schema and normalization.
		var upstream object
		if err := json.Unmarshal(result.Stdout, &upstream); err != nil {
			return nil, err
		}

		return normalizeUpstreamReport(upstream)
	}

	if kind != "scout" {
		return nil, errors.New("unknown comparison runtime")
	}

	document, err := decodeScoutDocument(result.Stdout)
	if err != nil {
		return nil, err
	}

	return normalizeScoutReport(document.Run.Targets[0].Analysis, document.Evaluation)
}

func comparisonAliases() map[string]string {
	return map[string]string{
		"PI001":   "P1",
		"PL001":   "P6",
		"AC003":   "BH1",
		"NV-TR1M": "TR1",
		"NV-TR2M": "TR2",
		"NV-TR3M": "TR3",
	}
}

func comparisonFamily(rule string) string {
	if alias := comparisonAliases()[rule]; alias != "" {
		return alias
	}

	originals := " SC001 SC002 SC003 AC001 AC002 AG001 AG002 MC001 MC002 MC003 BI001 EX001 SE001 FS001 GO001 GO002 GO003 GO004 SH001 SH002 SH003 SH004 DE001 MP001 PI002 PI003 NV-TR1 NV-TR2 NV-TR3 NV-SC7M "
	if strings.Contains(originals, " "+rule+" ") {
		return "scout:" + rule
	}

	return suiteFamily(rule)
}

func normalizeUpstreamReport(r object) (object, error) {
	findings := make([]object, 0)

	if boolean(r["mcp_registry"]) {
		for _, value := range array(r[findingsKey]) {
			f := obj(value)
			findings = append(findings, object{
				"rule":          f["id"],
				"original_rule": f["id"],
				"file":          filepath.Base(text(r["source"])),
				"line":          0,
				"severity":      f["severity"],
				"evidence_kind": f["evidence"],
			})
		}

		return object{
			findingsKey:            findings,
			coverageKey:            "registry_posture_only",
			"execution_successful": true,
			"server_count":         r["server_count"],
			"risk":                 r["risk_score"],
		}, nil
	}

	issues, ok := r["issues"].([]any)
	if !ok || !boolean(r["execution_successful"]) || text(at(r, "metadata", "skillspector_version")) != upstreamVersion || at(r, "metadata", "llm_requested") != false {
		return nil, errors.New("upstream report schema/runtime drift")
	}

	for _, value := range issues {
		f := obj(value)
		loc := obj(f["location"])
		findings = append(findings, object{
			"rule":          comparisonFamily(text(f["id"])),
			"original_rule": f["id"],
			"file":          loc["file"],
			"line":          number(loc["start_line"]),
			"severity":      strings.ToLower(text(f["severity"])),
		})
	}

	completeness := obj(r["analysis_completeness"])
	for _, status := range array(completeness["analyzer_statuses"]) {
		if boolean(at(status, "failed")) {
			return nil, errors.New("upstream analyzer failed")
		}
	}

	return object{
		findingsKey:            findings,
		coverageKey:            completeness["status"],
		"execution_successful": true,
		"analyzer_statuses":    completeness["analyzer_statuses"],
		"risk":                 r["risk_assessment"],
	}, nil
}

func normalizeScoutReport(r scanreport.Analysis, evaluation scanreport.Evaluation) (object, error) {
	if r.Inspection.Name != "standard" {
		return nil, errors.New("scout comparison requires standard profile")
	}

	objects := map[string]string{}

	for _, value := range r.Extraction.Objects {
		name := value.File.Path

		member := value.MemberName
		if member == "" {
			member = name
		}

		objects[name] = member
	}

	findings := make([]object, 0)

	for _, finding := range r.Findings {
		file := finding.Location.Path
		if name := objects[file]; name != "" {
			file = name
		}

		findings = append(findings, object{
			"rule":          comparisonFamily(finding.RuleID),
			"original_rule": finding.RuleID,
			"file":          file,
			"line":          finding.Location.StartLine,
			"severity":      finding.Severity,
		})
	}

	diagnostics := map[string]bool{}
	for _, diagnostic := range r.Diagnostics {
		diagnostics[diagnostic.Code] = true
	}

	return object{
		findingsKey:      findings,
		coverageKey:      string(r.Coverage.Completeness),
		"policy":         string(evaluation.Decision),
		"engine_version": r.EngineVersion,
		"diagnostics":    sortedKeys(diagnostics),
	}, nil
}

// New Scout observations must carry a valid v1 binding. Flat saved reports are
// never reinterpreted as current execution; external upstream evidence above
// remains explicitly governed by its separate historical schema.
func decodeScoutDocument(data []byte) (scanreport.Document, error) {
	var document scanreport.Document
	if len(data) > maxJSONLine {
		return document, errors.New("scout document exceeds byte budget")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&document) != nil {
		return scanreport.Document{}, errors.New("invalid scout document JSON")
	}

	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || document.Validate() != nil || document.Operation != scanreport.ScanOperation || len(document.Run.Targets) != 1 {
		return scanreport.Document{}, errors.New("scout requires one validated scan target")
	}

	return document, nil
}

func addComparisonDifferences(row object) {
	upstream, scoutFound := comparisonFindingSets(row["upstream"]), comparisonFindingSets(row["scout"])
	for _, pair := range []struct {
		Name string
		A, B map[string]bool
	}{{Name: "upstream", A: upstream, B: scoutFound}, {Name: "scout", A: scoutFound, B: upstream}} {
		only := difference(pair.A, pair.B)
		files := make([][]string, 0, len(only))
		familiesA, familiesB := map[string]bool{}, map[string]bool{}

		for _, key := range only {
			rule, file, _ := strings.Cut(key, "\x00")
			files = append(files, []string{rule, file})
		}

		for key := range pair.A {
			rule, _, _ := strings.Cut(key, "\x00")
			familiesA[rule] = true
		}

		for key := range pair.B {
			rule, _, _ := strings.Cut(key, "\x00")
			familiesB[rule] = true
		}

		row[pair.Name+"_only"], row[pair.Name+"_only_families"] = files, difference(familiesA, familiesB)
	}
}

func comparisonFindingSets(value any) map[string]bool {
	out := map[string]bool{}

	findings, ok := at(value, findingsKey).([]object)
	if !ok {
		return out
	}

	for _, f := range findings {
		out[text(f["rule"])+"\x00"+text(f["file"])] = true
	}

	return out
}

func materializeComparisonSource(root, upstream, target string, source object) error {
	kind, name := text(source["kind"]), text(source["path"])
	switch kind {
	case "authored_regression":
		return writeAuthoredFiles(target, obj(source["files"]))
	case "upstream_fixture_file":
		origin, err := safeJoin(upstream, name)
		if err != nil {
			return err
		}

		return copyFile(origin, filepath.Join(target, filepath.Base(name)))
	case "upstream_fixture", "scout_fixture":
		base := root
		if kind == "upstream_fixture" {
			base = upstream
		}

		origin, err := safeJoin(base, name)
		if err != nil {
			return err
		}

		return copyTree(origin, target)
	default:
		return fmt.Errorf("unknown comparison source kind %q", kind)
	}
}

func comparisonArgument(target string, spec object, kind, name string) (string, error) {
	argument := target
	if kind == "upstream_fixture_file" {
		argument = filepath.Join(target, filepath.Base(name))
	}

	if input := text(spec["input_file"]); input != "" {
		selected, err := safeJoin(target, input)
		if err != nil {
			return "", err
		}

		info, err := os.Stat(selected)
		if err != nil || !info.Mode().IsRegular() {
			return "", errors.New("comparison input file missing")
		}

		argument = selected
	}

	return argument, nil
}

func comparisonCoverageEntry(coverage object, name string, file inventoryFile) (object, error) {
	entry := obj(coverage[name])
	if entry == nil || text(entry["sha256"]) != file.SHA256 || number(entry["bytes"]) != file.Bytes {
		return nil, errors.New("fixture bytes differ from pinned coverage")
	}

	return entry, nil
}

func comparisonCorpusCoverage(spec object, pinned sourceInventory) (object, error) {
	if text(spec["upstream_commit"]) != upstreamCommit {
		return nil, errors.New("unexpected corpus source revision")
	}

	coverage := obj(spec["required_upstream_fixtures"])
	if coverage == nil {
		return nil, errors.New("fixture coverage metadata missing")
	}

	expected := map[string]bool{}

	for _, item := range pinned.Files {
		if strings.HasPrefix(item.Path, "tests/fixtures/") {
			expected[item.Path] = true
		}
	}

	if !slices.Equal(sortedKeys(coverage), sortedKeys(expected)) {
		return nil, errors.New("fixture inventory differs from pinned sources")
	}

	for _, value := range coverage {
		entry := obj(value)
		entry["package_cases"], entry["file_cases"] = []string{}, []string{}
	}

	return coverage, nil
}

func (p *comparisonPreparation) add(root, output, upstream string, spec object) error {
	tc, err := prepareComparisonCase(root, output, upstream, spec)
	if err != nil {
		return err
	}

	if err = recordFixtureCoverage(p.coverage, tc); err != nil {
		return err
	}

	p.cases = append(p.cases, tc)

	row, err := asObject(tc.Spec)
	if err != nil {
		return err
	}

	row["path"], row["inventory_root"], row["files"], row["sha256"] = tc.Argument, tc.Root, tc.Files, tc.SHA256
	p.exported = append(p.exported, row)

	if text(at(tc.Spec, "source", "kind")) == "upstream_fixture" {
		p.packageRoots[text(at(tc.Spec, "source", "path"))] = true
	}

	return nil
}

func validateComparisonCoverage(coverage object, packageRoots map[string]bool) error {
	for name, value := range coverage {
		entry := obj(value)
		if lenStringValues(entry["package_cases"]) == 0 || lenStringValues(entry["file_cases"]) == 0 {
			return errors.New("uncovered upstream fixture")
		}

		if path.Base(name) == "SKILL.md" && !packageRoots[path.Dir(name)] {
			return errors.New("missing skill package context")
		}
	}

	return nil
}

func expectedUpstreamRejection(spec object, kind string, result processResult) bool {
	return kind == "upstream" && text(spec["expected_upstream_rejection"]) == "invalid_registry_record" && result.Code == 2 && len(strings.TrimSpace(string(result.Stdout))) == 0 && strings.Contains(strings.Join(strings.Fields(string(result.Stderr)), " "), "MCP Registry payload has an invalid server record")
}
