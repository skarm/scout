package sqlsyntax_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/sqlsyntax"
)

func TestSQLTokensPreserveExecutableWordsAndQuotedData(t *testing.T) {
	text := "/* outer /* nested */ comment */ SELECT 'DROP; TABLE', \"TRUNCATE\", [DELETE], `UPDATE`; -- DROP\nTRUNCATE rows;"
	tree, err := sqlsyntax.Parse(context.Background(), text)
	if err != nil || len(tree.Statements) != 2 {
		t.Fatalf("%+v %v", tree, err)
	}
	var destructive []string
	for _, st := range tree.Statements {
		for _, token := range st.Tokens {
			if token.Start < 0 || token.End > len(text) || token.End <= token.Start {
				t.Fatal("invalid token coordinates")
			}
			if token.Kind == "word" && (token.Text == "DROP" || token.Text == "TRUNCATE" || token.Text == "DELETE" || token.Text == "UPDATE") {
				destructive = append(destructive, token.Text)
			}
		}
	}
	if strings.Join(destructive, ",") != "TRUNCATE" {
		t.Fatal(destructive)
	}
}

func TestSQLFailuresRetainEarlierStatements(t *testing.T) {
	for _, suffix := range []string{"SELECT 'unclosed", "SELECT (1", "/* unclosed", "SELECT $$unclosed"} {
		tree, err := sqlsyntax.Parse(context.Background(), "DROP TABLE accounts;"+suffix)
		if err == nil || len(tree.Statements) == 0 || tree.Statements[0].Tokens[0].Text != "DROP" {
			t.Fatalf("lost preceding evidence: %+v %v", tree, err)
		}
	}
	for _, text := range []string{strings.Repeat(" ", sqlsyntax.MaxBytes+1), strings.Repeat("(", sqlsyntax.MaxDepth+1), strings.Repeat("1 ", sqlsyntax.MaxTokens+1)} {
		if _, err := sqlsyntax.Parse(context.Background(), text); err == nil {
			t.Fatal("SQL budget silently exceeded")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sqlsyntax.Parse(ctx, ""); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestSQLProceduralBodyRemainsUnverified(t *testing.T) {
	tree, err := sqlsyntax.Parse(context.Background(), "DO $body$ BEGIN EXECUTE untrusted; END $body$;")
	if err != nil || !tree.Limited {
		t.Fatalf("opaque executable body certified: %+v %v", tree, err)
	}
}

func TestLineCommentsEndAtSQLNewlines(t *testing.T) {
	const comment = "-- DROP TABLE commented;"
	const command = "DROP TABLE accounts"
	for _, tc := range []struct{ name, newline string }{
		{name: "LF", newline: "\n"},
		{name: "CRLF", newline: "\r\n"},
		{name: "CR", newline: "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := comment + tc.newline + command + ";"
			tree, err := sqlsyntax.Parse(t.Context(), text)
			if err != nil || tree.Limited || len(tree.Statements) != 1 {
				t.Fatalf("statement after comment lost: %+v, %v", tree, err)
			}
			statement := tree.Statements[0]
			if statement.Start != len(comment)+len(tc.newline) || text[statement.Start:statement.End] != command ||
				len(statement.Tokens) != 3 || statement.Tokens[0].Kind != "word" || statement.Tokens[0].Text != "DROP" {
				t.Fatalf("incorrect statement or physical source span: %+v", statement)
			}
		})
	}
	tree, err := sqlsyntax.Parse(t.Context(), comment)
	if err != nil || len(tree.Statements) != 0 {
		t.Fatalf("comment at EOF became a statement: %+v, %v", tree, err)
	}
}

func TestSQLWhitespacePreservesStatements(t *testing.T) {
	const command = "DROP TABLE accounts"
	for _, whitespace := range []string{" ", "\t", "\n", "\r", "\f", "\v"} {
		text := whitespace + command + ";"
		tree, err := sqlsyntax.Parse(t.Context(), text)
		if err != nil || len(tree.Statements) != 1 {
			t.Fatalf("whitespace %q: %+v, %v", whitespace, tree, err)
		}
		statement := tree.Statements[0]
		if statement.Start != len(whitespace) || text[statement.Start:statement.End] != command ||
			len(statement.Tokens) != 3 || statement.Tokens[0].Text != "DROP" {
			t.Fatalf("whitespace %q changed statement tokens or span: %+v", whitespace, statement)
		}
	}
}
