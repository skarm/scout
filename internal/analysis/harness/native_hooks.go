package harness

import (
	"fmt"
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/report"
)

func (p *plugin) nativeHooks(e *entry, n *jsonconfig.Node, parent, activation string) {
	hooks := n.Get(fieldHooks)
	if hooks == nil {
		hooks = n
	}

	if hooks.Kind != jsonconfig.KindObject {
		p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for event, member := range hooks.Members {
		if !p.b.step() {
			return
		}

		if member.Value.Kind != jsonconfig.KindArray {
			p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		for i, handler := range member.Value.Elements {
			if !p.b.step() {
				return
			}

			s := ref(e, handler.Span)
			id := p.component(report.ComponentHook, e, activation, basisConfiguration, s, fmt.Sprintf("native-hook:%d:%d", event, i))
			p.b.edge(parent, id, relationRegisters, basisConfiguration, activation, s)

			runs := agentconfig.HookRuns(p.host, handler)
			if len(runs) == 0 {
				p.issue(issuePluginHookTypeUnverified, e.Meta.Path, report.OutcomePartial)
			}

			for _, run := range runs {
				p.nativeHookRun(e, handler, run, id, activation)
			}
		}
	}
}

func (p *plugin) nativeHookRun(e *entry, n *jsonconfig.Node, run agentconfig.HookRun, id, activation string) {
	s := ref(e, run.Value.Span)

	text := run.Value.String
	if run.Field == "exec" {
		args, valid := stringValues(n.Get(fieldArgs))
		if !valid {
			p.issue(issuePluginHookArgsInvalid, e.Meta.Path, formatInvalid)
			return
		}

		p.nativeCommand(id, append([]string{text}, args...), n.Get("cwd"), s, activation)

		return
	}

	if run.Field == "powershell" {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, "native_powershell_hook_unverified", "", s)
		return
	}

	launch, err := shellsyntax.Parse(p.b.ctx, text)

	cmd, simple := hooktrace.SimpleShellCommand(launch)
	if err != nil || !simple {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reasonComplexShellCommand, "", s)
		return
	}

	words := make([]string, 0, len(cmd.Words))
	for _, word := range cmd.Words {
		literal, ok := word.Literal()
		if !ok {
			p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reasonDynamicCommand, "", s)
			return
		}

		words = append(words, literal)
	}

	p.nativeCommand(id, words, n.Get("cwd"), s, activation)
}

// nativeCommand links an argv launch only inside the captured workspace/package.
// The working directory is a static relative path; runtime resolution is unknown.
func (p *plugin) nativeCommand(id string, words []string, cwd *jsonconfig.Node, s *report.SourceRef, activation string) {
	if len(words) == 0 || words[0] == "" {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reasonInvalidCommandBytes, "", s)
		return
	}

	base := "."

	if cwd != nil {
		value, ok := cwd.Text()

		var reason string

		base, reason = artifactpath.Reference(value, false)
		if !ok || reason != "" {
			p.reference(id, referenceKindCommand, report.ReferenceUnresolved, "working_directory_unknown", "", s)
			return
		}
	}

	name, runtime, reason := commandOperand(words)
	if reason != "" {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reason, "", s)
		return
	}

	if runtime {
		p.reference(id, referenceKindRuntime, report.ReferenceUnresolved, report.ReferenceReasonRuntimeNotMaterialized, "", s)
	}

	if !strings.Contains(name, "/") || path.IsAbs(name) {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, "external_command_not_materialized", "", s)
		return
	}

	rel, reason := artifactpath.Reference(name, false)
	if reason != "" {
		p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reason, "", s)
		return
	}

	if e := p.entry(path.Join(base, rel)); e != nil && e.Doc != nil {
		p.capturedHandler(id, e, activation, s)
	} else {
		p.reference(id, referenceKindHandler, report.ReferenceUnresolved, report.ReferenceReasonHandlerNotCaptured, "", s)
	}
}
