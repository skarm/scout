// Package hooktrace follows bounded hook paths through captured documents.
package hooktrace

import (
	"iter"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// Sources holds bounded static paths and their unresolved edges.
type Sources struct {
	Paths       []Path
	Diagnostics []report.Diagnostic
	Commands    []Command
}

type Command struct {
	report.SourceRef
	FileArgv bool // traced file invocation with no outer shell text
}

type Path struct {
	Target     string
	Event      string
	HostOutput bool
	Language   string
	Steps      []report.SourceRef
	Scope      source.Span
	Exclude    []source.Span
}

// File is a captured namespace entry. Doc can be absent for uncaptured content.
type File struct {
	Meta report.File
	Doc  *document.File
}

// FileTree exposes captured entries under a single plugin root. Descendants
// yields names relative to the supplied directory in namespace order.
type FileTree interface {
	LookupFile(string) *File
	HasDirectory(string) bool
	Descendants(string) iter.Seq[string]
}

// Scope describes the host and the captured files visible to one hook declaration.
type Scope struct {
	Host            string
	Inactive        bool
	ProjectSettings bool
	Files           FileTree
}

// Tracer collects paths, commands and diagnostics in declaration order and
// consumes operation budget shared with its caller.
type Tracer struct {
	work            *analysisbudget.Sequence
	shellRoot       report.ShellHookRoot
	references      int
	diagnosticLimit func()
	sources         Sources
	seen            map[report.Diagnostic]struct{}
}

func New(work *analysisbudget.Sequence, shellRoot report.ShellHookRoot, references int, diagnosticLimit func()) *Tracer {
	return &Tracer{work: work, shellRoot: shellRoot, references: references, diagnosticLimit: diagnosticLimit}
}

func (t *Tracer) Sources() Sources { return t.sources }

// Trace follows a validated command hook. It returns the paths added for this
// declaration and whether the command budget was exhausted.
func (t *Tracer) Trace(e *File, hook *jsonconfig.Node, event, matcher string, scope Scope) ([]Path, bool) {
	mode, _ := hook.Get("shell").Text()
	if hook.Get("shell") != nil && mode != language.ExecutableBash && mode != language.ExecutableSh {
		return nil, false
	}

	command := hook.Get("command")
	commandText, _ := command.Text()

	initial := e.SourceRef(command.Span)
	if initial == nil {
		return nil, false
	}

	if len(t.sources.Commands) >= t.references {
		return nil, true
	}

	start := len(t.sources.Paths)
	walk := hookSourceWalk{
		trace: t, scope: scope, config: e, event: event, active: map[string]bool{}, origins: map[string]*document.File{e.Meta.Path: e.Doc},
		bashFallback: mode == language.ExecutableBash && hook.Get("args") == nil,
	}

	args := hook.Get("args")

	if scope.Host == report.HostGeminiCLI && strings.Contains(commandText, geminiExtensionPath) {
		t.sources.Commands = append(t.sources.Commands, Command{SourceRef: *initial})
		walk.geminiLaunch(commandText, args, *initial)

		return t.sources.Paths[start:], false
	}

	fileArgv := args != nil && walk.argv(e, command, args, *initial)

	t.sources.Commands = append(t.sources.Commands, Command{SourceRef: *initial, FileArgv: fileArgv})

	for _, unit := range e.Doc.Units() {
		if unit.Origin != document.OriginHookShell || unit.Span.Start < hook.Span.Start || unit.Span.End > hook.Span.End {
			continue
		}

		if tree, ok := unit.Tree.(parse.ShellTree); ok {
			shell := hookSourceTree(tree)
			walk.rootLaunch = nil

			if walk.assumesShellHookRoot() && args == nil && unit.View.Text() == commandText &&
				shell != nil && !shell.OmittedExecution {
				// The supplied root is made up of shell inert characters.
				// Only use it in a single entry command, before shell state can
				// change. Captured files still need their own expansion proof.
				if launch, simple := SimpleShellCommand(shell); simple {
					walk.rootLaunch = launch
				}
			}

			state := walk.initialHookSourceState(shell, hook, matcher, args == nil && unit.View.Text() == commandText)
			walk.commands(e, unit.View, shell, state, nil, true)
		}
	}

	return t.sources.Paths[start:], false
}

func (w *hookSourceWalk) assumesShellHookRoot() bool {
	host := w.trace.shellRoot.Host

	return host != "" && (host == w.scope.Host || host == report.HostAuto &&
		(pluginRootParameters[w.scope.Host] != "" || w.scope.Host == report.HostGeminiCLI))
}

func (w *hookSourceWalk) seedHookLocale(state *hookSourceState) {
	if locale := w.trace.shellRoot.LCAll; locale != "" && w.assumesShellHookRoot() {
		state.bindValue("LC_ALL", locale, true)
	}
}

func (e *File) SourceRef(s source.Span) *report.SourceRef {
	if e == nil || e.Doc == nil {
		return nil
	}

	f := e.Doc.Artifact()

	text := f.Content()
	if s.Start < 0 || s.End < s.Start || s.End > len(text) {
		return nil
	}

	return &report.SourceRef{
		Path:       e.Meta.Path,
		SHA256:     e.Meta.SHA256,
		ByteStart:  s.Start,
		ByteEnd:    s.End,
		SpanSHA256: artifact.Hash([]byte(text[s.Start:s.End])),
	}
}
