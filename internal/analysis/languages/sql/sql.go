package sql

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
	"github.com/skarm/scout/report"
)

type sqlCheck struct{ id string }

func (a sqlCheck) Rule() report.Rule {
	title, category := "", ""

	switch a.id {
	case ruleSQL001:
		title, category = "SQL declares destructive or unscoped data modification", "destructive-database-operation"
	case ruleSQL002:
		title, category = "SQL expands database authority or bypasses row security", "database-authority"
	case ruleSQL003:
		title, category = "SQL requests server filesystem or program access", "database-external-io"
	case ruleSQL004:
		title, category = "SQL disables a database execution limit", "resource-limits"
	}

	severity := report.High
	if a.id == ruleSQL004 {
		severity = report.Medium
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
		Title:       title,
		Description: title,
		Severity:    severity,
		Category:    category,
		Method:      "sql-token-statements",
		Limitation:  "Bounded SQL token/statement structure with separate comments, quoted strings and identifiers. Selected PostgreSQL/MySQL/SQLite/T-SQL signals; not a database grammar, schema resolver or authorization decision. Migrations and maintenance may legitimately match. Dynamic procedural bodies remain incomplete.",
	}
}

func (sqlCheck) AppliesTo(f document.File) bool {
	for _, u := range f.Units() {
		if u.Language == language.SQL {
			return true
		}
	}

	return false
}

func (a sqlCheck) Find(ctx context.Context, f document.File, budget int) (result, error) {
	var out result

	for _, u := range f.Units() {
		tree, ok := u.Tree.(sqlsyntax.Tree)
		if !ok {
			continue
		}

		for _, st := range tree.Statements {
			if err := ctx.Err(); err != nil {
				return out, err
			}

			if !analysisbudget.Consume(ctx, uint64(len(st.Tokens)+1)) {
				out.Truncated = true
				return out, nil
			}

			if !a.matches(st.Tokens) {
				continue
			}

			if len(out.Matches) >= budget {
				out.Truncated = true
				return out, nil
			}

			span, err := u.View.Original(source.Span{Start: st.Start, End: st.End})
			if err != nil {
				return out, errors.New("SQL evidence mapping failed")
			}

			out.Matches = append(out.Matches, match{Start: span.Start, End: span.End})
		}
	}

	return out, ctx.Err()
}

func (a sqlCheck) matches(ts []sqlsyntax.Token) bool {
	if len(ts) == 0 || ts[0].Kind != "word" {
		return false
	}

	command := ts[0].Text

	switch a.id {
	case ruleSQL001:
		return sqlDestructive(command, ts)
	case ruleSQL002:
		return sqlAuthority(command, ts)
	case ruleSQL003:
		return sqlExternalIO(command, ts)
	case ruleSQL004:
		return sqlExecutionLimits(command, ts)
	}

	return false
}

func sqlDestructive(command string, ts []sqlsyntax.Token) bool {
	if command == "TRUNCATE" || command == "DROP" {
		return true
	}

	if command == "DELETE" || command == "UPDATE" {
		return !sqlWords(ts, "WHERE")
	}

	return command == "WITH" && (sqlWords(ts, "DELETE") || sqlWords(ts, "UPDATE"))
}

func sqlAuthority(command string, ts []sqlsyntax.Token) bool {
	if command == "ALTER" || command == "CREATE" {
		return sqlWords(ts, "SUPERUSER") || sqlWords(ts, "BYPASSRLS") || sqlWords(ts, "SECURITY", "DEFINER") || sqlWords(ts, "DISABLE", "ROW", "LEVEL", "SECURITY")
	}

	if command == "GRANT" {
		return sqlWords(ts, "ALL") || sqlWords(ts, "PUBLIC") || sqlWords(ts, "SUPERUSER")
	}

	return command == "SET" && sqlWords(ts, "ROW_SECURITY") && sqlDisabled(ts)
}

func sqlExternalIO(command string, ts []sqlsyntax.Token) bool {
	if command == "COPY" && (sqlWords(ts, "PROGRAM") || sqlFileCopy(ts)) {
		return true
	}

	return sqlCall(ts, "PG_READ_FILE") || sqlCall(ts, "PG_READ_BINARY_FILE") || sqlCall(ts, "LO_EXPORT") || sqlWords(ts, "EXEC", "XP_CMDSHELL") || sqlWords(ts, "EXECUTE", "XP_CMDSHELL") || sqlWords(ts, "INTO", "OUTFILE") || sqlCall(ts, "LOAD_FILE") || sqlWords(ts, "LOAD", "DATA", "INFILE")
}

func sqlExecutionLimits(command string, ts []sqlsyntax.Token) bool {
	if command != "SET" && command != "PRAGMA" {
		return false
	}

	setting := sqlWords(ts, "STATEMENT_TIMEOUT") || sqlWords(ts, "LOCK_TIMEOUT") || sqlWords(ts, "IDLE_IN_TRANSACTION_SESSION_TIMEOUT") || sqlWords(ts, "MAX_EXECUTION_TIME") || sqlWords(ts, "BUSY_TIMEOUT")

	return setting && sqlDisabled(ts)
}

func sqlCall(ts []sqlsyntax.Token, name string) bool {
	for i, t := range ts {
		if t.Kind == "word" && t.Text == name && i+1 < len(ts) && ts[i+1].Kind == "punctuation" && ts[i+1].Text == "(" {
			return true
		}
	}

	return false
}

func sqlWords(ts []sqlsyntax.Token, words ...string) bool {
	for i := 0; i+len(words) <= len(ts); i++ {
		matched := true
		for j, word := range words {
			matched = matched && ts[i+j].Kind == "word" && ts[i+j].Text == word
		}

		if matched {
			return true
		}
	}

	return false
}

func sqlDisabled(ts []sqlsyntax.Token) bool {
	for _, t := range ts {
		if (t.Kind == "word" || t.Kind == "string") && (t.Text == "0" || strings.EqualFold(t.Text, "off") || strings.EqualFold(t.Text, "unlimited") || t.Text == "0ms" || t.Text == "0s") {
			return true
		}
	}

	return false
}

func sqlFileCopy(ts []sqlsyntax.Token) bool {
	for i, t := range ts {
		if i+1 < len(ts) && t.Kind == "word" && (t.Text == "TO" || t.Text == "FROM") && ts[i+1].Kind == "string" {
			return true
		}
	}

	return false
}
