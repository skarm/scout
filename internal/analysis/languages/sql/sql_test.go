package sql_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/sql"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestExecutionLimitUsesAssignedValue(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       int
	}{
		{"bounded first", "SET SESSION max_execution_time = 1000, sql_safe_updates = 0;", 0},
		{"bounded second", "SET SESSION sql_safe_updates = 0, max_execution_time = 1000;", 0},
		{"disabled first", "SET SESSION max_execution_time = 0, sql_safe_updates = 1;", 1},
		{"disabled second", "SET SESSION sql_safe_updates = 1, max_execution_time = 0;", 1},
		{"postgres bounded", "SET statement_timeout TO '1000ms';", 0},
		{"postgres disabled", "SET LOCAL statement_timeout TO '0ms';", 1},
		{"sqlite bounded", "PRAGMA busy_timeout(1000);", 0},
		{"sqlite disabled", "PRAGMA busy_timeout(0);", 1},
		{"qualified pragma", "PRAGMA main.busy_timeout = 0;", 1},
		{"parenthesized zero", "SET max_execution_time = ((0));", 1},
		{"signed zero", "SET max_execution_time = -0;", 1},
		{"qualified system variable", "SET @@SESSION.max_execution_time := 0;", 1},
		{"user variable", "SET @max_execution_time = 0;", 0},
		{"value reference", "SET @x = @@max_execution_time + 0;", 0},
		{"computed bounded value", "SET max_execution_time = 0 + 1000;", 0},
		{"nested comma", "SET @x = CONCAT('a', '0'), max_execution_time = 1000;", 0},
		{"comment boundary", "SET sql_safe_updates = 0, /* limit */ max_execution_time = 1000;", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := document.Prepare(t.Context(), artifact.NewFile("budget.sql", []byte(tc.text), false))
			for _, rule := range sql.Rules() {
				if rule.Rule().ID != "SQL004" {
					continue
				}
				result, err := rule.Find(t.Context(), file, 10)
				if err != nil || result.Truncated || len(result.Matches) != tc.want {
					t.Fatalf("SQL004 matches=%d want=%d truncated=%v err=%v", len(result.Matches), tc.want, result.Truncated, err)
				}
				return
			}
			t.Fatal("SQL004 not registered")
		})
	}
}

func TestScannerExecutionLimitAssignments(t *testing.T) {
	options := scout.DefaultOptions()
	options.Profile = scout.Custom
	options.Checks = &scout.Checks{}
	scanner, err := scout.New(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, value := range []string{"1000", "0", "1000"} {
		statement := "SET SESSION sql_safe_updates = 0, max_execution_time = " + value
		for _, fenced := range []bool{false, true} {
			name, text := "budget.sql", statement+";"
			if fenced {
				name, text = "notes.md", "# Example🙂\r\n\r\n> ```sql\r\n> "+statement+";\r\n> ```\r\n"
			}
			run, scanErr := scanner.Scan(t.Context(), scout.Reader(name, strings.NewReader(text)))
			if scanErr != nil && !errors.Is(scanErr, scout.ErrIncomplete) {
				t.Fatal(scanErr)
			}
			if err := report.ValidateSealedRun(run); err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, target := range run.Targets {
				for _, finding := range target.Analysis.Findings {
					if finding.RuleID != "SQL004" {
						continue
					}
					count++
					start, end := finding.Location.ByteStart, finding.Location.ByteEnd
					if start < 0 || end > len(text) || start >= end || text[start:end] != statement {
						t.Fatalf("incorrect SQL evidence: %+v", finding.Location)
					}
					hash := sha256.Sum256([]byte(statement))
					if finding.Evidence.SpanSHA256 != hex.EncodeToString(hash[:]) {
						t.Fatal("SQL evidence hash does not bind original source")
					}
				}
			}
			want := 0
			if value == "0" {
				want = 1
			}
			if count != want {
				t.Fatalf("value=%s fenced=%v: SQL004 count=%d want=%d", value, fenced, count, want)
			}
		}
	}
}

func TestSchemaSearchPathIsNotRowSecurityAssignment(t *testing.T) {
	for _, text := range []string{
		"SET search_path TO row_security, off;",
		"SET search_path = off, row_security;",
	} {
		file := document.Prepare(t.Context(), artifact.NewFile("schema.sql", []byte(text), false))
		for _, rule := range sql.Rules() {
			if rule.Rule().ID != "SQL002" {
				continue
			}
			result, err := rule.Find(t.Context(), file, 10)
			if err != nil || result.Truncated || len(result.Matches) != 0 {
				t.Fatalf("schema search path changed row-security observation: %+v, %v", result, err)
			}
		}
	}
}

func TestDestructiveStatementAfterLexicalWhitespaceRetainsEvidence(t *testing.T) {
	const command = "DROP TABLE accounts"
	for _, tc := range []struct{ name, prefix string }{
		{name: "CR comment", prefix: "-- DROP TABLE commented;\r"},
		{name: "vertical tab", prefix: "\v"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.prefix + command + ";"
			file := document.Prepare(t.Context(), artifact.NewFile("migration.sql", []byte(text), false))
			checkDestructiveStatement(t, file, text, len(tc.prefix), command)
		})
	}
}

func checkDestructiveStatement(t *testing.T, file document.File, text string, start int, command string) {
	t.Helper()
	for _, rule := range sql.Rules() {
		if rule.Rule().ID != "SQL001" {
			continue
		}
		result, err := rule.Find(t.Context(), file, 10)
		if err != nil || result.Truncated || len(result.Matches) != 1 {
			t.Fatalf("destructive statement lost after lexical whitespace: %+v, %v", result, err)
		}
		match := result.Matches[0]
		if match.Start != start || match.End != start+len(command) || text[match.Start:match.End] != command {
			t.Fatalf("finding cites the comment or loses source coordinates: %+v", match)
		}
		return
	}
	t.Fatal("SQL001 is not registered")
}
