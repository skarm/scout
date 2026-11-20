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

const (
	keywordWhere                           = "WHERE"
	keywordGrant                           = "GRANT"
	keywordSet                             = "SET"
	keywordPragma                          = "PRAGMA"
	keywordCopy                            = "COPY"
	keywordTo                              = "TO"
	keywordFrom                            = "FROM"
	keywordSession                         = "SESSION"
	keywordLocal                           = "LOCAL"
	keywordGlobal                          = "GLOBAL"
	keywordPersist                         = "PERSIST"
	keywordPersistOnly                     = "PERSIST_ONLY"
	keywordStatementTimeout                = "STATEMENT_TIMEOUT"
	keywordLockTimeout                     = "LOCK_TIMEOUT"
	keywordIdleInTransactionSessionTimeout = "IDLE_IN_TRANSACTION_SESSION_TIMEOUT"
	keywordMaxExecutionTime                = "MAX_EXECUTION_TIME"
	keywordBusyTimeout                     = "BUSY_TIMEOUT"
)

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
	if len(ts) == 0 || ts[0].Kind != sqlsyntax.KindWord {
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
	if command == sqlsyntax.KeywordTruncate || command == sqlsyntax.KeywordDrop {
		return true
	}

	if command == sqlsyntax.KeywordDelete || command == sqlsyntax.KeywordUpdate {
		return !sqlOuterWhere(ts)
	}

	return command == sqlsyntax.KeywordWith && sqlWithModifiesRows(ts)
}

func sqlWithModifiesRows(ts []sqlsyntax.Token) bool {
	for i, tok := range ts {
		if tok.Kind != sqlsyntax.KindWord {
			continue
		}

		switch tok.Text {
		case sqlsyntax.KeywordDelete:
			return true
		case sqlsyntax.KeywordUpdate:
			// SELECT locking clauses may occur in the main statement or a CTE.
			if !sqlWords(ts[max(0, i-1):i], "FOR") && !sqlWords(ts[max(0, i-3):i], "FOR", "NO", "KEY") {
				return true
			}
		}
	}

	return false
}

func sqlOuterWhere(ts []sqlsyntax.Token) bool {
	depth := 0

	for _, tok := range ts {
		switch tok.Kind {
		case sqlsyntax.KindPunctuation:
			switch tok.Text {
			case "(":
				depth++
			case ")":
				depth--
			}
		case sqlsyntax.KindWord:
			if depth == 0 && tok.Text == keywordWhere {
				return true
			}
		}
	}

	return false
}

func sqlAuthority(command string, ts []sqlsyntax.Token) bool {
	if command == sqlsyntax.KeywordAlter || command == sqlsyntax.KeywordCreate {
		return sqlWords(ts, "SUPERUSER") || sqlWords(ts, "BYPASSRLS") || sqlWords(ts, "SECURITY", "DEFINER") || sqlWords(ts, "DISABLE", "ROW", "LEVEL", "SECURITY")
	}

	if command == keywordGrant {
		return sqlWords(ts, "ALL") || sqlWords(ts, "PUBLIC") || sqlWords(ts, "SUPERUSER")
	}

	if command != keywordSet {
		return false
	}

	name, disabled := sqlDisabledAssignment(command, ts[1:])

	return name == "ROW_SECURITY" && disabled
}

func sqlExternalIO(command string, ts []sqlsyntax.Token) bool {
	if command == keywordCopy && (sqlWords(ts, "PROGRAM") || sqlFileCopy(ts)) {
		return true
	}

	return sqlCall(ts, "PG_READ_FILE") || sqlCall(ts, "PG_READ_BINARY_FILE") || sqlCall(ts, "LO_EXPORT") || sqlWords(ts, sqlsyntax.KeywordExec, "XP_CMDSHELL") || sqlWords(ts, sqlsyntax.KeywordExecute, "XP_CMDSHELL") || sqlWords(ts, "INTO", "OUTFILE") || sqlCall(ts, "LOAD_FILE") || sqlWords(ts, "LOAD", "DATA", "INFILE")
}

func sqlExecutionLimits(command string, ts []sqlsyntax.Token) bool {
	if command != keywordSet && command != keywordPragma {
		return false
	}

	// MySQL permits several assignments in one SET. A value from a different
	// assignment, or from a nested expression, cannot disable this setting.
	start, depth := 1, 0

	for i := 1; i < len(ts); i++ {
		if ts[i].Kind != sqlsyntax.KindPunctuation {
			continue
		}

		switch ts[i].Text {
		case "(":
			depth++
		case ")":
			depth--
		case ",":
			if depth == 0 {
				if sqlLimitAssignment(command, ts[start:i]) {
					return true
				}

				start = i + 1
			}
		}
	}

	return sqlLimitAssignment(command, ts[start:])
}

func sqlLimitAssignment(command string, ts []sqlsyntax.Token) bool {
	name, disabled := sqlDisabledAssignment(command, ts)
	return sqlLimitName(name) && disabled
}

func sqlDisabledAssignment(command string, ts []sqlsyntax.Token) (string, bool) {
	ts = sqlSettingTarget(command, ts)
	if len(ts) < 3 || ts[0].Kind != sqlsyntax.KindWord {
		return "", false
	}

	value := ts[2:]
	switch {
	case ts[1].Kind == sqlsyntax.KindPunctuation && ts[1].Text == "=":
	case ts[1].Kind == sqlsyntax.KindWord && ts[1].Text == keywordTo:
	case ts[1].Text == ":" && len(value) > 0 && value[0].Text == "=":
		value = value[1:]
	case command == keywordPragma && ts[1].Text == "(" && ts[len(ts)-1].Text == ")":
		value = value[:len(value)-1]
	default:
		return "", false
	}
	// Only an isolated disabled literal is proven here. In particular, a zero
	// operand in an unevaluated expression is not its resulting value.
	for len(value) >= 3 && value[0].Text == "(" && value[len(value)-1].Text == ")" {
		value = value[1 : len(value)-1]
	}

	if len(value) == 2 && (value[0].Text == "+" || value[0].Text == "-") && value[1].Kind == sqlsyntax.KindWord && value[1].Text == "0" {
		value = value[1:]
	}

	return ts[0].Text, len(value) == 1 && sqlDisabled(value)
}

func sqlSettingTarget(command string, ts []sqlsyntax.Token) []sqlsyntax.Token {
	if command == keywordPragma && len(ts) >= 2 && ts[1].Text == "." {
		ts = ts[2:]
	}

	if len(ts) > 0 && ts[0].Kind == sqlsyntax.KindWord {
		switch ts[0].Text {
		case keywordSession, keywordLocal, keywordGlobal, keywordPersist, keywordPersistOnly:
			ts = ts[1:]
		}
	}

	if len(ts) >= 2 && ts[0].Text == "@" && ts[1].Text == "@" {
		ts = ts[2:]
		if len(ts) >= 2 && ts[1].Text == "." {
			ts = ts[2:]
		}
	}

	return ts
}

func sqlLimitName(name string) bool {
	switch name {
	case keywordStatementTimeout, keywordLockTimeout, keywordIdleInTransactionSessionTimeout, keywordMaxExecutionTime, keywordBusyTimeout:
		return true
	default:
		return false
	}
}

func sqlCall(ts []sqlsyntax.Token, name string) bool {
	for i, t := range ts {
		if t.Kind == sqlsyntax.KindWord && t.Text == name && i+1 < len(ts) && ts[i+1].Kind == sqlsyntax.KindPunctuation && ts[i+1].Text == "(" {
			return true
		}
	}

	return false
}

func sqlWords(ts []sqlsyntax.Token, words ...string) bool {
	for i := 0; i+len(words) <= len(ts); i++ {
		matched := true
		for j, word := range words {
			matched = matched && ts[i+j].Kind == sqlsyntax.KindWord && ts[i+j].Text == word
		}

		if matched {
			return true
		}
	}

	return false
}

func sqlDisabled(ts []sqlsyntax.Token) bool {
	for _, t := range ts {
		if (t.Kind == sqlsyntax.KindWord || t.Kind == sqlsyntax.KindString) && (t.Text == "0" || strings.EqualFold(t.Text, "off") || strings.EqualFold(t.Text, "unlimited") || t.Text == "0ms" || t.Text == "0s") {
			return true
		}
	}

	return false
}

func sqlFileCopy(ts []sqlsyntax.Token) bool {
	for i, t := range ts {
		if i+1 < len(ts) && t.Kind == sqlsyntax.KindWord && (t.Text == keywordTo || t.Text == keywordFrom) && ts[i+1].Kind == sqlsyntax.KindString {
			return true
		}
	}

	return false
}
