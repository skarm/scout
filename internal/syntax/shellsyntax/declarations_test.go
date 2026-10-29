package shellsyntax_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

func TestDeclarationProjectionBodyAndQuotes(t *testing.T) {
	for _, tc := range []struct {
		delimiter, body string
		quoted          bool
	}{
		{delimiter: "EOF", body: "registry=$SRC\n", quoted: false},
		{delimiter: "'EOF'", body: "registry=$SRC\n", quoted: true},
		{delimiter: "EOF", body: "registry=https://пример.invalid\n", quoted: false},
		{delimiter: "END$OF", body: "registry=$SRC\n", quoted: false},
		{delimiter: "END'$'OF", body: "registry=$SRC\n", quoted: true},
	} {
		text := "cat > .npmrc <<" + tc.delimiter + "\n" + tc.body + strings.ReplaceAll(tc.delimiter, "'", "") + "\n"
		tree, e := shellsyntax.ParseDeclarations(context.Background(), text)
		if e != nil {
			t.Fatal(e)
		}
		redirs := tree.Statements[0].Commands[0].Redirects
		r := redirs[len(redirs)-1]
		if r.Body == nil || text[r.Body.Span.Start:r.Body.Span.End] != tc.body || r.QuotedDelimiter != tc.quoted {
			t.Fatalf("physical heredoc boundary: %+v", r)
		}
	}
	text := "SRC='Привет🙂'; if :; then npm config set registry \"$SRC\"; fi"
	tree, e := shellsyntax.ParseDeclarations(context.Background(), text)
	if e != nil {
		t.Fatal(e)
	}
	v, ok := tree.Statements[0].Commands[0].Assignments[0].Value.Literal()
	if !ok || v != "Привет🙂" {
		t.Fatalf("literal corrupted: %q", v)
	}
}

func TestDeclarationProjectionBudgets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := shellsyntax.ParseDeclarations(ctx, "npm install"); e == nil {
		t.Fatal("cancel ignored")
	}
	for _, text := range []string{strings.Repeat("x", shellsyntax.MaxBytes+1), strings.Repeat("if :; then ", shellsyntax.MaxDepth+2) + ":" + strings.Repeat("; fi", shellsyntax.MaxDepth+2)} {
		_, e := shellsyntax.ParseDeclarations(context.Background(), text)
		if _, ok := errors.AsType[*shellsyntax.Error](e); !ok {
			t.Fatalf("limit not reported: %v", e)
		}
	}
}

func TestDeclarationProjectionWhileAndUnknownEffectBarrier(t *testing.T) {
	tree, err := shellsyntax.ParseDeclarations(context.Background(), "while :; do npm config set registry https://example.invalid; done")
	if err != nil {
		t.Fatal(err)
	}
	command := tree.Statements[0].Commands[0]
	if command.Prelude == nil || len(command.Prelude.Statements) != 1 || len(command.Alternatives) != 2 || len(command.Alternatives[0].Statements) != 1 || len(command.Alternatives[1].Statements) != 0 {
		t.Fatal("while projection lost condition, body or zero-iteration alternative")
	}
	tree, err = shellsyntax.ParseDeclarations(context.Background(), "((count++))")
	if err != nil {
		t.Fatal(err)
	}
	command = tree.Statements[0].Commands[0]
	if len(command.Invalidates) != 1 || command.Invalidates[0] != "*" {
		t.Fatal("unknown execution effect did not form a variable barrier")
	}
}
