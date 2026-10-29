//nolint:testpackage // Tests verify private comparison admission and evidence publication contracts.
package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestComparisonPreparationBindsWholePackagesAndSingleFiles(t *testing.T) {
	root, upstream, output, pinned := comparisonCorpus(t)
	cases, err := prepareComparison(root, output, upstream, pinned)
	if err != nil || len(cases) != 2 {
		t.Fatalf("corpus preparation failed: %v", err)
	}
	for _, tc := range cases {
		if len(tc.Files) != 1 || tc.SHA256 == "" {
			t.Fatal("case lost its byte inventory")
		}
	}
	if filepath.Ext(cases[1].Argument) != ".md" || cases[0].Argument != cases[0].Root {
		t.Fatal("single-file/package boundaries merged")
	}
	var coverage object
	if err := readJSON(filepath.Join(output, "fixture-coverage.json"), &coverage); err != nil {
		t.Fatal(err)
	}
	entry := obj(at(coverage, "files", "tests/fixtures/pkg/SKILL.md"))
	if len(array(entry["package_cases"])) != 1 || len(array(entry["file_cases"])) != 1 {
		t.Fatal("fixture coverage lost a context")
	}
	authored := object{
		"id": "authored",
		"source": object{
			"kind":  "authored_regression",
			"files": object{"nested/input.py": "inert"},
		},
		"input_file": "nested/input.py",
	}
	tc, err := prepareComparisonCase(root, output, upstream, authored)
	if err != nil || filepath.Base(tc.Argument) != "input.py" {
		t.Fatal("authored input selection failed")
	}
	maintenanceFile(t, root, "testdata/scout/SKILL.md", []byte("local"))
	if _, err := prepareComparisonCase(root, output, upstream, object{
		"id": "scout",
		"source": object{
			"kind": "scout_fixture",
			"path": "testdata/scout",
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []object{{"source": object{"kind": "authored_regression"}}, {
		"id":     "bad",
		"source": object{"kind": "unknown"},
	}, {
		"id": "escape",
		"source": object{
			"kind":  "authored_regression",
			"files": object{"../outside": "bytes"},
		},
	}, {
		"id":         "missing",
		"source":     object{"kind": "authored_regression"},
		"input_file": "missing.py",
	}} {
		if _, err := prepareComparisonCase(root, output, upstream, spec); err == nil {
			t.Fatal("invalid case materialization was accepted")
		}
	}
}

func TestComparisonRuntimePlansAndCancelledRunsStayExplicit(t *testing.T) {
	root, upstream, output, pinned := comparisonCorpus(t)
	scanner := maintenanceFile(t, t.TempDir(), "scanner", []byte("trusted binary identity"))
	fields := map[string]*string{
		"upstream-source": &upstream,
		"skillspector":    &scanner,
		"scout":           &scanner,
		"output":          &output,
	}
	selected, err := selectComparison(options{root: root, values: fields})
	if err != nil || selected.upstream != upstream || selected.scanner != scanner {
		t.Fatalf("comparison selection changed: %v", err)
	}
	upstreamArgs := comparisonCommand("upstream", "mcp_registry", scanner, scanner, "/input with spaces")
	scoutArgs := comparisonCommand("scout", "static", scanner, scanner, "--input")
	if !reflect.DeepEqual(upstreamArgs, []string{scanner, "scan", "--format", "json", "--no-llm", "--mcp-registry", "/input with spaces"}) || scoutArgs[len(scoutArgs)-2] != "--" {
		t.Fatal("comparison argv crossed a shell/argument boundary")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := compareUpstream(ctx, options{root: root, values: fields}, io.Discard); err == nil {
		t.Fatal("unverified/cancelled oracle ran")
	}
	directory := filepath.Join(t.TempDir(), "comparison")
	fsSession := comparisonSession{
		root:        root,
		upstream:    upstream,
		scanner:     scanner,
		scoutBinary: scanner,
		output:      directory,
	}
	environment, err := fsSession.prepareFilesystem(ctx)
	if err == nil {
		t.Fatal("cancelled network-denial stage passed")
	}
	for _, name := range []string{"home", "tmp", "reports"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatal("private workflow directory missing")
		}
	}
	selected.output = output
	if err := selected.writeEnvironment(pinned, externalRuntime{}); err != nil {
		t.Fatal(err)
	}
	var metadata object
	if err := readJSON(filepath.Join(output, "environment.json"), &metadata); err != nil {
		t.Fatal(err)
	}
	if number(metadata["source_inventory_files"]) != pinned.FileCount || text(metadata["source_commit"]) != upstreamCommit || text(metadata["scout_binary_sha256"]) != digest([]byte("trusted binary identity")) {
		t.Fatal("comparison metadata lost verified source/binary identities", metadata)
	}
	cases, err := prepareComparison(root, output, upstream, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runComparisonCase(ctx, output, environment.home, environment.profile, environment.env, scanner, scanner, cases[0]); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled same-byte comparison ran")
	}
	tc := preparedCase{Root: t.TempDir(), Spec: object{"id": "empty"}, Files: []inventoryFile{}}
	row := object{
		"upstream": object{findingsKey: []object{{"rule": "P1", "file": "SKILL.md"}}},
		"scout":    object{findingsKey: []object{}},
	}
	if _, err := finalizeComparisonCase(row, tc); err != nil || len(row["upstream"+"_only"].([][]string)) != 1 {
		t.Fatal("comparison lost family/file differences")
	}
	maintenanceFile(t, tc.Root, "changed", []byte("new bytes"))
	if _, err := finalizeComparisonCase(row, tc); err == nil {
		t.Fatal("changed package accepted")
	}
}

func TestComparisonPersistsRawStreamsAndRetainsSchemaFailures(t *testing.T) {
	output := t.TempDir()
	if err := os.Mkdir(filepath.Join(output, "reports"), 0o700); err != nil {
		t.Fatal(err)
	}
	process := processResult{Stdout: []byte("malformed JSON"), Stderr: []byte("diagnostic"), Code: 2}
	if err := writeComparisonStreams(output, "case", "scout", process); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "reports/case.scout.json"))
	if err != nil || !bytes.Equal(data, process.Stdout) {
		t.Fatal("raw report bytes changed")
	}
	observation := comparisonObservation(object{}, "scout", process)
	if observation[errorKey] == nil || observation["report_sha256"] != digest(process.Stdout) {
		t.Fatal("schema failure or raw-byte identity lost")
	}
	results := comparisonResults{rows: []object{}, rejections: []string{}}
	var progress bytes.Buffer
	row := object{"id": "case", "scout": observation, "upstream": object{"expected_rejection": true}}
	if err := results.add(preparedCase{Spec: object{"id": "case"}}, row, 1, &progress); err != nil {
		t.Fatal(err)
	}
	if err := results.finish(output, 1); err == nil {
		t.Fatal("comparison schema failures reported success")
	}
	if _, err := os.Stat(filepath.Join(output, "comparison.json")); err != nil {
		t.Fatal("failed comparison discarded evidence")
	}
}

func TestHistoricalUpstreamNormalizationRetainsItsSeparateSchema(t *testing.T) {
	upstream := object{
		"issues": []any{object{
			"id": "PI001",
			"location": object{
				"file":       "SKILL.md",
				"start_line": float64(3),
			},
			"severity": "HIGH",
		}},
		"execution_successful": true,
		"metadata": object{
			"skillspector_version": upstreamVersion,
			"llm_requested":        false,
		},
		"analysis_completeness": object{
			"status":            "complete",
			"analyzer_statuses": []any{},
		},
	}
	data, _ := json.Marshal(upstream)
	normalized, err := normalizeComparisonResult(object{}, "upstream", processResult{Stdout: data})
	if err != nil || normalized[findingsKey].([]object)[0]["rule"] != "P1" {
		t.Fatal("historical family normalization changed")
	}
	if comparisonFamily("SC001") != "scout:SC001" || comparisonFamily("NV-TR1") != "scout:NV-TR1" || suiteFamily("PY-AST1") != "AST1" {
		t.Fatal("current/external family identities merged")
	}
	registry, err := normalizeUpstreamReport(object{
		"mcp_registry": true,
		"source":       "/path/registry.json",
		findingsKey:    []any{object{"id": "rule"}},
	})
	if err != nil || registry[coverageKey] != "registry_posture_only" {
		t.Fatal("registry posture acquired execution semantics")
	}
	rejected, err := normalizeComparisonResult(object{"expected_upstream_rejection": "invalid_registry_record"}, "upstream", processResult{
		Code:   2,
		Stderr: []byte("MCP Registry payload has an invalid server record"),
	})
	if err != nil || rejected["expected_rejection"] != true {
		t.Fatal("explicit historical rejection lost")
	}
	if _, err := normalizeComparisonResult(object{}, "unknown", processResult{}); err == nil {
		t.Fatal("unknown runtime accepted")
	}
	if _, err := normalizeUpstreamReport(object{}); err == nil {
		t.Fatal("historical schema drift accepted")
	}
	upstream["analysis_completeness"] = object{"analyzer_statuses": []any{object{"failed": true}}}
	if _, err := normalizeUpstreamReport(upstream); err == nil {
		t.Fatal("upstream failure accepted")
	}
}

func TestUpstreamSuitePlansPersistExactArgumentsAndExitEvidence(t *testing.T) {
	root, upstream, _, _ := comparisonCorpus(t)
	python := filepath.Join(t.TempDir(), "venv/bin/python")
	output := filepath.Join(t.TempDir(), "suite")
	session, err := selectUpstreamSuite(options{
		root: root,
		values: map[string]*string{
			"upstream": &upstream,
			"python":   &python,
			"output":   &output,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := session.verifyAndRun(ctx, io.Discard); err == nil {
		t.Fatal("unverified interpreter executed")
	}
	if err := session.prepareFilesystem(ctx); err == nil {
		t.Fatal("cancelled denial probe accepted")
	}
	args := session.command()
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "pytest_asyncio.plugin") || !strings.Contains(joined, "addopts=") || !strings.Contains(joined, "--basetemp="+filepath.Join(output, "pytest-tmp")) {
		t.Fatal("pytest command permissions/capture plan changed")
	}
	if err := session.writeMetadata(args); err != nil {
		t.Fatal(err)
	}
	if err := session.execute(ctx, io.Discard); err == nil {
		t.Fatal("cancelled pytest execution accepted")
	}
	var response bytes.Buffer
	if err := session.publishExit(0, &response); err != nil {
		t.Fatal(err)
	}
	if err := session.publishExit(1, &response); err == nil {
		t.Fatal("failed pytest suite was reported as passing")
	}
	if _, err := os.Stat(filepath.Join(output, "exit.json")); err != nil {
		t.Fatal("exit evidence not retained")
	}
}

func TestFixtureCoverageRejectsUncoveredFilesAndMissingPackageContext(t *testing.T) {
	coverage := object{"tests/pkg/SKILL.md": object{"package_cases": []string{}, "file_cases": []string{"file"}}}
	if err := validateComparisonCoverage(coverage, map[string]bool{}); err == nil {
		t.Fatal("uncovered package accepted")
	}
	obj(coverage["tests/pkg/SKILL.md"])["package_cases"] = []string{"case"}
	if err := validateComparisonCoverage(coverage, map[string]bool{}); err == nil {
		t.Fatal("missing package context accepted")
	}
	if err := validateComparisonCoverage(coverage, map[string]bool{"tests/pkg": true}); err != nil {
		t.Fatal(err)
	}
}

func TestComparisonVerificationPrecedesOutputCreation(t *testing.T) {
	root, upstream, _, _ := comparisonCorpus(t)
	scanner := maintenanceFile(t, t.TempDir(), "scanner", []byte("inert identity; never executable"))
	output := filepath.Join(t.TempDir(), "not-created")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := compareUpstream(ctx, options{
		root: root,
		values: map[string]*string{
			"upstream-source": &upstream,
			"skillspector":    &scanner,
			"scout":           &scanner,
			"output":          &output,
		},
	}, io.Discard)
	if err == nil {
		t.Fatal("unverified/cancelled comparison succeeded")
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("verification failure created comparison output: %v", statErr)
	}
}

func comparisonCorpus(t *testing.T) (string, string, string, sourceInventory) {
	t.Helper()
	root, upstream, output := t.TempDir(), t.TempDir(), t.TempDir()
	data := []byte("inert fixture\n")
	name := "tests/fixtures/pkg/SKILL.md"
	maintenanceFile(t, upstream, name, data)
	var pinned sourceInventory
	inventory := object{
		"Commit":     upstreamCommit,
		"file_count": 1,
		"Files": []any{object{
			"Path":   name,
			"SHA256": digest(data),
			"Bytes":  len(data),
		}},
	}
	path := maintenanceJSON(t, root, "testdata/provenance/upstream-inventory.json", inventory)
	if err := readJSON(path, &pinned); err != nil {
		t.Fatal(err)
	}
	cases := []any{
		object{"id": "package", "source": object{"kind": "upstream_fixture", "path": "tests/fixtures/pkg"}},
		object{"id": "file", "source": object{"kind": "upstream_fixture_file", "path": name}},
	}
	maintenanceJSON(t, root, "testdata/differential/cases.json", object{
		"upstream_commit": upstreamCommit,
		"required_upstream_fixtures": object{name: object{
			"sha256": digest(data),
			"bytes":  len(data),
		}},
		"cases": cases,
	})
	return root, upstream, output, pinned
}
