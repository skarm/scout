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
