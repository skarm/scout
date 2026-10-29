package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestReportContractDoesNotImportRuntime(t *testing.T) {
	root := filepath.Join("..", "..", "report")
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal("public report contract is missing: ", err)
	}
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Split(path, "/")[0], ".") {
				t.Errorf("report must be independent of runtime and dependencies: %s imports %s", entry.Name(), path)
			}
		}
	}
}

// Execution consumes check contracts directly. The registry's aliases are an
// implementation convenience for its own checks, not a second contract owner.
func TestCheckConsumersUseOwningPackage(t *testing.T) {
	root := filepath.Join("..", "..")
	visitProductionSource(t, root, func(_ string, file *ast.File, positions *token.FileSet) {
		registry := ""
		for _, spec := range file.Imports {
			if spec.Path.Value == `"github.com/skarm/scout/internal/analysis/analyzer"` {
				registry = "analyzer"
				if spec.Name != nil {
					registry = spec.Name.Name
				}
			}
		}
		if registry == "" {
			return
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if ok && owner.Name == registry && slices.Contains([]string{"Analyzer", "Match", "Trace", "Result"}, selector.Sel.Name) {
				t.Errorf("%s: use check.%s from the contract owner", positions.Position(selector.Pos()), selector.Sel.Name)
			}
			return true
		})
	})
}

func TestEngineImportsRegistryOnlyDuringPreparation(t *testing.T) {
	visitProductionSource(t, filepath.Join("..", ".."), func(path string, file *ast.File, _ *token.FileSet) {
		if !strings.HasPrefix(path, "internal/analysis/engine/") || path == "internal/analysis/engine/execution.go" {
			return
		}
		for _, spec := range file.Imports {
			if spec.Path.Value == `"github.com/skarm/scout/internal/analysis/analyzer"` {
				t.Errorf("%s: registry binding belongs to execution preparation; use shared contracts and file classification directly", path)
			}
		}
	})
}

func TestPackageDependencyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		root      string
		forbidden []string
	}{
		{
			root:      "osv",
			forbidden: []string{"internal/syntax/frontend", "internal/signatures", "internal/analysis/dependencies", "internal/analysis/document", "internal/syntax/parse"},
		},
		{
			root:      "internal/analysis/update",
			forbidden: []string{"internal/syntax/frontend", "internal/signatures", "internal/analysis/dependencies", "internal/analysis/document", "internal/syntax/parse"},
		},
		{
			root:      "internal/dev/provenance",
			forbidden: []string{"internal/dev/maintenance", "internal/syntax/frontend", "internal/signatures", "internal/analysis/engine", "internal/analysis/analyzer"},
		},
		{root: "internal/commands/devcli", forbidden: []string{"internal/commands/cli"}},
		{
			root:      "cmd/scout",
			forbidden: []string{"internal/dev", "internal/commands/devcli", "internal/scantest", "tests"},
		},
		{root: ".", forbidden: []string{"internal/dev", "internal/commands", "internal/scantest", "tests"}},
		{
			root:      "internal/analysis/sourcepolicy",
			forbidden: []string{"internal/analysis/analyzer", "internal/analysis/languages", "internal/commands", "internal/dev"},
		},
	} {
		t.Run(tc.root, func(t *testing.T) {
			imports := localDependencies(t, tc.root, map[string]bool{})
			for imported := range imports {
				for _, forbidden := range tc.forbidden {
					if imported == forbidden || strings.HasPrefix(imported, forbidden+"/") {
						t.Errorf("%s must not depend on %s", tc.root, imported)
					}
				}
			}
		})
	}
}

func TestLanguageAnalyzersRemainIndependent(t *testing.T) {
	const prefix = "internal/analysis/languages/"
	shared := []string{"internal/analysis/check", "internal/analysis/document", "internal/analysis/analysisbudget", "internal/analysis/securitytext", "internal/analysis/sourcepolicy", prefix + "literals", "internal/buildinfo", "internal/capture/artifact", "internal/syntax", "internal/textmatch", "report"}
	for _, name := range productionPackages(t, strings.TrimSuffix(prefix, "/")) {
		t.Run(name, func(t *testing.T) {
			owner := prefix + strings.Split(strings.TrimPrefix(name, prefix), "/")[0]
			for imported := range localDependencies(t, name, map[string]bool{}) {
				if withinPackage(imported, owner) || slices.ContainsFunc(shared, func(allowed string) bool { return withinPackage(imported, allowed) }) {
					continue
				}
				t.Errorf("language package %s depends on %s outside its language and shared contracts", name, imported)
			}
		})
	}
}

func TestSyntaxBackendsDoNotDependOnAnalysis(t *testing.T) {
	for _, name := range productionPackages(t, "internal/syntax") {
		t.Run(name, func(t *testing.T) {
			for imported := range localDependencies(t, name, map[string]bool{}) {
				if withinPackage(imported, "internal/syntax") || imported == "report" || imported == "internal/textmatch" || imported == "internal/buildinfo" {
					continue
				}
				t.Errorf("syntax package %s depends on higher-level package %s", name, imported)
			}
		})
	}
}

func TestCaptureDoesNotDependOnAnalysisOrCommands(t *testing.T) {
	for _, name := range productionPackages(t, "internal/capture") {
		t.Run(name, func(t *testing.T) {
			for imported := range localDependencies(t, name, map[string]bool{}) {
				allowed := []string{"internal/buildinfo", "internal/capture", "internal/syntax", "internal/netpolicy", "internal/textmatch", "fetch", "report"}
				if !slices.ContainsFunc(allowed, func(prefix string) bool { return withinPackage(imported, prefix) }) {
					t.Errorf("capture package %s depends on higher-level package %s", name, imported)
				}
			}
		})
	}
}

// The generic registry may delegate to language packages, but cannot walk or
// select concrete source-language parsers itself, even in inactive build files.
func TestGeneralAnalyzerDelegatesLanguageSyntax(t *testing.T) {
	root := filepath.Join("..", "analysis", "analyzer")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"go/ast", "go/parser", "github.com/skarm/scout/internal/syntax/frontend", "github.com/skarm/scout/internal/syntax/shellsyntax", "github.com/skarm/scout/internal/syntax/scriptsyntax", "github.com/skarm/scout/internal/syntax/sqlsyntax"}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(forbidden, imported) {
				t.Errorf("generic analyzer %s imports language syntax %s", entry.Name(), imported)
			}
		}
	}
}

// Parse every production file, including inactive build variants. This guards
// package boundaries without loading native engines or invoking the Go toolchain.
func localDependencies(t *testing.T, name string, seen map[string]bool) map[string]bool {
	t.Helper()
	if seen[name] {
		return seen
	}

	seen[name] = true
	directory := filepath.Join("..", "..", filepath.FromSlash(name))
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}

		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}

			if imported == "github.com/skarm/scout" {
				localDependencies(t, ".", seen)
			} else if local, ok := strings.CutPrefix(imported, "github.com/skarm/scout/"); ok {
				localDependencies(t, local, seen)
			}
		}
	}

	return seen
}

// Discover every production package, including future languages and subpackages.
// Testdata remains inert even when a fixture happens to contain a .go file.
func productionPackages(t *testing.T, name string) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	found := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(name)), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		found[filepath.ToSlash(relative)] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	packages := make([]string, 0, len(found))
	for name := range found {
		packages = append(packages, name)
	}
	slices.Sort(packages)
	if len(packages) == 0 {
		t.Fatalf("no production packages under %s", name)
	}
	return packages
}

func withinPackage(name, prefix string) bool {
	return name == prefix || strings.HasPrefix(name, prefix+"/")
}
