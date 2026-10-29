package shell

import (
	"context"
	"iter"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var shellPatternCommands = stringSet("curl wget rm chmod git cp mv install")

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	removalCommands    = stringSet("rm /bin/rm /usr/bin/rm del erase")
	removalLongOptions = map[string]removalFlags{
		"--":          removalOptionsEnded,
		"--recursive": removalRecursive,
		"--force":     removalForce,
	}
	removalShortOptions = map[rune]removalFlags{'r': removalRecursive, 'R': removalRecursive, 'f': removalForce}
)

// PatternOptions separates syntax observations from generic pattern policy.
type PatternOptions struct {
	Mode          PatternMode
	LanguageFacts check.LanguageFacts
	MatchText     func(context.Context, string) bool
}

type shellPatternWalker struct {
	options     PatternOptions
	ctx         context.Context
	budget, ops int
	out         result
	seen        map[source.Span]bool
	halted      bool
}

type removalFlags uint8

const (
	removalRecursive removalFlags = 1 << iota
	removalForce
	removalOptionsEnded
)

type removalInvocation struct {
	flags removalFlags
	broad bool
}

type PatternMode uint8

const (
	PatternNone PatternMode = iota
	PatternTransmission
	PatternRemoval
	PatternPersistence
	PatternDownload
)

// Patterns observes mapped shell commands using a caller-owned literal policy.
// Parsed words handle quote concatenation and physical line wrapping. Commands
// are never resolved or executed; unknown words remain unknown.
func Patterns(ctx context.Context, d document.File, options PatternOptions, budget int) (result, error) {
	var out result

	sharedOrdinary := false

	shared := options.LanguageFacts[d.Artifact().Metadata().Path]
	if options.Mode == PatternDownload && shared != nil {
		sharedOrdinary = true

		var err error

		out, err = shared.Rules[ruleNVSC2].Result(budget)
		if err != nil {
			return out, err
		}
	}

	p := shellPatternWalker{options: options, ctx: ctx, budget: budget, out: out}

	p.seen = map[source.Span]bool{}
	for _, match := range p.out.Matches {
		p.seen[source.Span{Start: match.Start, End: match.End}] = true
	}

	for _, unit := range d.Units() {
		if !sharedOrdinary {
			p.preparedUnit(unit)
		}
	}

	candidates, limited := d.ShellCandidates()
	for _, unit := range candidates {
		p.preparedUnit(unit)
	}

	p.out.Truncated = p.out.Truncated || limited

	return p.out, ctx.Err()
}

// A declaration projection can accept a different continuation extent than the
// execution grammar. Choose its paired tree/view together, before walking it.
func (p *shellPatternWalker) preparedUnit(unit document.Unit) {
	parsed, ok := unit.Tree.(parse.ShellTree)
	if !ok {
		return
	}

	tree, view := parsed.Tree, unit.View
	if p.options.Mode == PatternDownload && parsed.Declarations != nil {
		tree = parsed.Declarations
		if parsed.DeclarationView != nil {
			view = *parsed.DeclarationView
		}
	}

	p.walk(tree, view, 0)
}

func (p *shellPatternWalker) walk(tree *shellsyntax.File, view source.View, depth int) {
	a := p.options
	out := &p.out

	if tree == nil || p.halted {
		return
	}

	if depth > 32 {
		out.Truncated = true
		return
	}

	if a.Mode == PatternDownload {
		p.downloadPatterns(tree, view)
		return
	}

	for _, statement := range tree.Statements {
		for _, command := range statement.Commands {
			if !p.command(command, view) {
				p.halted = true
				return
			}

			for child := range shellNestedTrees(command) {
				p.walk(child, view, depth+1)
			}
		}
	}
}

func (p *shellPatternWalker) step() bool {
	p.ops++
	if p.ops > 8192 || !analysisbudget.Consume(p.ctx, 1) {
		p.halted, p.out.Truncated = true, true
	}

	return !p.halted
}

func shellNestedTrees(command *shellsyntax.Command) iter.Seq[*shellsyntax.File] {
	return func(yield func(*shellsyntax.File) bool) {
		if !yield(command.Subshell) {
			return
		}

		for _, word := range command.Words {
			for _, part := range word.Parts {
				if part.Kind == "substitution" && !yield(part.Tree) {
					return
				}
			}
		}
	}
}

func (p *shellPatternWalker) downloadPatterns(tree *shellsyntax.File, view source.View) {
	ctx, budget, out, seen := p.ctx, p.budget, &p.out, p.seen
	// Reuse the bounded download-to-execution analysis, including shell
	// continuations, quote concatenation, wrappers and stdio ownership.
	// Markdown candidates have their own mapped view; no flattened text
	// or fabricated offsets are needed.
	result, operations, err := observeDownload(ctx, tree, view, budget+1, p.ops)
	p.ops = operations
	p.halted = err != nil || result.Truncated

	out.Truncated = out.Truncated || result.Truncated || err != nil
	for _, m := range result.Matches {
		at := source.Span{Start: m.Start, End: m.End}
		if !seen[at] {
			if len(out.Matches) >= budget {
				p.halted = true
				out.Truncated = true

				return
			}

			seen[at] = true

			out.Matches = append(out.Matches, m)
		}
	}
}

func shellPatternWords(command *shellsyntax.Command, mode PatternMode) []string {
	words := make([]string, 0, len(command.Words))

	for _, word := range command.Words {
		v, ok := word.Literal()
		if !ok && mode == PatternPersistence {
			var literal strings.Builder

			ok = true

			for _, part := range word.Parts {
				if part.Kind != "literal" {
					ok = false
					break
				}

				literal.WriteString(part.Text)
			}

			v = literal.String()
		}

		if !ok {
			v = "__scout_unknown_word__"
		}

		if len(words) > 0 {
			v = strings.NewReplacer("\r", "__scout_word_break__", "\n", "__scout_word_break__").Replace(v)
		}

		words = append(words, v)
	}

	return words
}

func (p *shellPatternWalker) command(command *shellsyntax.Command, view source.View) bool {
	if !p.step() {
		return false
	}

	if !p.options.matchesShellCommand(p.ctx, command) {
		return true
	}

	at, err := view.Original(command.Span)
	if err != nil || p.seen[at] {
		return true
	}

	p.seen[at] = true
	if len(p.out.Matches) >= p.budget {
		p.out.Truncated = true
		return false
	}

	p.out.Matches = append(p.out.Matches, match{Start: at.Start, End: at.End})

	return true
}

func persistentCopy(words []string) bool {
	if len(words) < 3 || (words[0] != "cp" && words[0] != "mv" && words[0] != "install") {
		return false
	}

	destination := words[len(words)-1]
	for _, root := range []string{"/.claude/skills/", "/.codex/skills/", "/.gemini/skills/", "/Library/LaunchAgents/", "/.config/autostart/"} {
		if strings.Contains(destination, root) {
			return true
		}
	}

	return false
}

func (a PatternOptions) matchesShellCommand(ctx context.Context, command *shellsyntax.Command) bool {
	words := shellPatternWords(command, a.Mode)
	if len(words) > 0 && a.Mode == PatternRemoval && removalCommands[words[0]] {
		return unsafeRemoval(command)
	}

	if len(words) == 0 || !shellPatternCommands[words[0]] {
		return false
	}

	matched := a.MatchText(ctx, strings.Join(words, " "))

	return matched || a.Mode == PatternPersistence && persistentCopy(words)
}

func (r *removalInvocation) option(value string) {
	if flags, known := removalLongOptions[value]; known {
		r.flags |= flags
		return
	}

	if strings.HasPrefix(value, "--") {
		return
	}

	for _, flag := range value[1:] {
		r.flags |= removalShortOptions[flag]
	}
}

func (r *removalInvocation) argument(word *shellsyntax.Word) {
	value, literal := word.Literal()
	if !literal {
		var known bool

		value, known = shellRemovalWord(word)
		if !known {
			return
		}
	}

	if literal && r.flags&removalOptionsEnded == 0 && strings.HasPrefix(value, "-") {
		r.option(value)
		return
	}

	r.broad = r.broad || value == "/" || !word.Quoted && removalBroadTarget(value)
}

func unsafeRemoval(command *shellsyntax.Command) bool {
	if len(command.Words) == 0 {
		return false
	}

	name, known := command.Words[0].Literal()
	if !known || !removalCommands[name] {
		return false
	}

	var invocation removalInvocation
	for _, word := range command.Words[1:] {
		invocation.argument(word)
	}

	return invocation.broad && invocation.flags&(removalRecursive|removalForce) == removalRecursive|removalForce
}

func shellRemovalWord(word *shellsyntax.Word) (string, bool) {
	var b strings.Builder

	for _, p := range word.Parts {
		if p.Kind != "literal" {
			return "", false
		}

		b.WriteString(p.Text)
	}

	return b.String(), true
}
