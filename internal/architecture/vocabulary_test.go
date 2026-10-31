package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Inspect inactive build variants too: a core-only run must protect the native
// adapters from reintroducing parallel copies of protocol vocabulary.
func TestSharedVocabularyHasOneOwner(t *testing.T) {
	root := filepath.Join("..", "..")
	ruleIdentity := regexp.MustCompile(`^(?:(?:AC|SC|MC|PI|AG|BH|PL|EX|SE|FS|BI|AE|DS|DE|MP|P|PE|EA|E|OH|TM|RA|AS|AR|SSRF|TR|NET|TC|XF|YR|OSV|GO|JS|AST|TT|SH|SQL|HI|RX)[0-9]{1,3}M?|(?:NV|PY)-[A-Z]+[0-9]{1,3}M?|MCP-[A-Z-]+)$`)
	for _, domain := range []struct {
		owner  string
		scopes []string
	}{
		{"report/hosts.go", []string{"report/validation.go", "options.go", "internal/analysis", "internal/distribution/integrations/pack.go"}},
		{"knowledge/modes.go", []string{"knowledge", "review", "internal/analysis/semantic", "internal/commands/cli/knowledge.go", "internal/dev/maintenance/knowledge_runtime.go"}},
		{"review/providers.go", []string{"review", "internal/commands/cli", "internal/commands/config"}},
		{"report/dependency_values.go", []string{"internal/analysis/dependencies", "osv"}},
		{"internal/analysis/analyzer/rule_ids.go", []string{"internal/analysis/analyzer"}},
		{"internal/analysis/bundle/rule_ids.go", []string{"internal/analysis/bundle"}},
		{"internal/analysis/engine/rule_ids.go", []string{"internal/analysis/engine"}},
		{"internal/analysis/languages/golang/rule_ids.go", []string{"internal/analysis/languages/golang"}},
		{"internal/analysis/languages/javascript/rule_ids.go", []string{"internal/analysis/languages/javascript"}},
		{"internal/analysis/languages/python/rule_ids.go", []string{"internal/analysis/languages/python"}},
		{"internal/analysis/languages/shell/rule_ids.go", []string{"internal/analysis/languages/shell"}},
		{"internal/analysis/languages/sql/rule_ids.go", []string{"internal/analysis/languages/sql"}},
		{"internal/analysis/rendertext/rule_ids.go", []string{"internal/analysis/rendertext"}},
	} {
		t.Run(domain.owner, func(t *testing.T) {
			values := vocabularyValues(t, filepath.Join(root, filepath.FromSlash(domain.owner)))
			visitProductionSource(t, root, func(path string, file *ast.File, positions *token.FileSet) {
				if path == domain.owner || !slices.ContainsFunc(domain.scopes, func(scope string) bool { return withinPackage(path, scope) }) {
					return
				}
				ast.Inspect(file, func(node ast.Node) bool {
					switch value := node.(type) {
					case *ast.ImportSpec, *ast.Field:
						return false
					case *ast.ValueSpec:
						// AWS SigV4's service identity is distinct from provider selection.
						if path == "review/messages.go" && len(value.Names) == 1 && value.Names[0].Name == "bedrockSigningService" {
							return false
						}
					case *ast.BasicLit:
						if value.Kind == token.STRING {
							text, err := strconv.Unquote(value.Value)
							if err != nil {
								t.Fatal(err)
							}
							if name, owned := values[text]; owned {
								t.Errorf("%s: use %s from %s instead of %q", positions.Position(value.Pos()), name, domain.owner, text)
							} else if strings.HasSuffix(domain.owner, "/rule_ids.go") && ruleIdentity.MatchString(text) {
								t.Errorf("%s: declare %q in %s, including IDs used only once", positions.Position(value.Pos()), text, domain.owner)
							}
						}
					}
					return true
				})
			})
		})
	}
}

// Input aliases, shell command names and JSON property names are intentionally
// literals. Only canonical labels in language fields belong to this vocabulary.
func TestLanguageFieldsUseCanonicalIdentifiers(t *testing.T) {
	root := filepath.Join("..", "..")
	values := vocabularyValues(t, filepath.Join(root, "internal", "syntax", "language", "ids.go"))
	visitProductionSource(t, root, func(_ string, file *ast.File, positions *token.FileSet) {
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.KeyValueExpr:
				if key, ok := value.Key.(*ast.Ident); ok && (key.Name == "Language" || key.Name == "language") {
					checkLanguageLiteral(t, value.Value, values, positions)
				}
			case *ast.BinaryExpr:
				if languageSelector(value.X) {
					checkLanguageLiteral(t, value.Y, values, positions)
				}
				if languageSelector(value.Y) {
					checkLanguageLiteral(t, value.X, values, positions)
				}
			}
			return true
		})
	})
}

func TestStatusFieldsUseReportVocabulary(t *testing.T) {
	root := filepath.Join("..", "..")
	values := map[string]string{}
	for _, owner := range []string{"report/outcomes.go", "report/inspection.go", "report/model.go"} {
		for value, name := range vocabularyValues(t, filepath.Join(root, filepath.FromSlash(owner))) {
			if strings.HasPrefix(name, "Outcome") || strings.HasPrefix(name, "Unit") || strings.HasPrefix(name, "Capture") {
				values[value] = name
			}
		}
	}

	visitProductionSource(t, root, func(_ string, file *ast.File, positions *token.FileSet) {
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.KeyValueExpr:
				if key, ok := value.Key.(*ast.Ident); ok && key.Name == "Status" {
					checkOwnedLiteral(t, value.Value, values, "report.", positions)
				}
			case *ast.BinaryExpr:
				if statusSelector(value.X) {
					checkOwnedLiteral(t, value.Y, values, "report.", positions)
				}
				if statusSelector(value.Y) {
					checkOwnedLiteral(t, value.X, values, "report.", positions)
				}
			case *ast.AssignStmt:
				if len(value.Lhs) == len(value.Rhs) {
					for i, target := range value.Lhs {
						if statusSelector(target) {
							checkOwnedLiteral(t, value.Rhs[i], values, "report.", positions)
						}
					}
				}
			}
			return true
		})
	})
}

func statusSelector(node ast.Expr) bool {
	selector, ok := node.(*ast.SelectorExpr)
	return ok && (selector.Sel.Name == "Status" || selector.Sel.Name == "ReadStatus")
}

func TestConfigurationFieldsUseNodeKinds(t *testing.T) {
	root := filepath.Join("..", "..")
	values := vocabularyValues(t, filepath.Join(root, "internal", "syntax", "jsonconfig", "kinds.go"))
	visitProductionSource(t, root, func(path string, file *ast.File, positions *token.FileSet) {
		configuration := strings.HasPrefix(path, "internal/syntax/jsonconfig/")
		for _, imported := range file.Imports {
			configuration = configuration || imported.Path.Value == `"github.com/skarm/scout/internal/syntax/jsonconfig"`
		}
		if !configuration {
			return
		}

		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.KeyValueExpr:
				if key, ok := value.Key.(*ast.Ident); ok && key.Name == "Kind" {
					checkOwnedLiteral(t, value.Value, values, "jsonconfig.", positions)
				}
			case *ast.BinaryExpr:
				if kindSelector(value.X) {
					checkOwnedLiteral(t, value.Y, values, "jsonconfig.", positions)
				}
				if kindSelector(value.Y) {
					checkOwnedLiteral(t, value.X, values, "jsonconfig.", positions)
				}
			case *ast.SwitchStmt:
				if kindSelector(value.Tag) {
					for _, statement := range value.Body.List {
						if branch, ok := statement.(*ast.CaseClause); ok {
							for _, expression := range branch.List {
								checkOwnedLiteral(t, expression, values, "jsonconfig.", positions)
							}
						}
					}
				}
			}
			return true
		})
	})
}

func kindSelector(node ast.Expr) bool {
	selector, ok := node.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Kind"
}

func languageSelector(node ast.Expr) bool {
	selector, ok := node.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Language"
}

func checkLanguageLiteral(t *testing.T, node ast.Expr, values map[string]string, positions *token.FileSet) {
	t.Helper()
	checkOwnedLiteral(t, node, values, "language.", positions)
}

func checkOwnedLiteral(t *testing.T, node ast.Expr, values map[string]string, prefix string, positions *token.FileSet) {
	t.Helper()
	literal, ok := node.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return
	}
	text, err := strconv.Unquote(literal.Value)
	if err != nil {
		t.Fatal(err)
	}
	if name, owned := values[text]; owned {
		t.Errorf("%s: use %s%s instead of %q", positions.Position(literal.Pos()), prefix, name, text)
	}
}

func vocabularyValues(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, expression := range value.Values {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				values[text] = value.Names[i].Name
			}
		}
	}
	if len(values) == 0 {
		t.Fatalf("no vocabulary constants in %s", path)
	}
	return values
}

func visitProductionSource(t *testing.T, root string, visit func(string, *ast.File, *token.FileSet)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, path, nil, 0)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		visit(filepath.ToSlash(relative), file, positions)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
