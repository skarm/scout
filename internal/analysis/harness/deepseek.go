package harness

import (
	"fmt"
	"path"
	"slices"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

func deepSeekCandidate(ns *namespace, name, requested string) (candidate, bool) {
	dir := path.Dir(name)

	c := candidate{ns: ns, root: dir, host: report.HostDeepSeekHarness, manifest: name, nativeWorkspace: true}
	if root, ok := artifact.DeepSeekSkillRoot(name, requested); ok {
		c.root = root
		return c, true
	}

	e := ns.entries[name]
	switch {
	case artifact.DeepSeekCordisName(name), artifact.DeepSeekSettingsName(name, requested):
		return c, true
	case path.Base(name) == "package.json":
		return c, agentconfig.DeepSeekManifest(capturedJSON(e))
	case requested == report.HostDeepSeekHarness && dir == ".":
		return c, artifact.DeepSeekYAMLName(name) && deepSeekStandalonePatch(e) ||
			len(ns.names) == 1 && path.Ext(name) == ".md" && deepSeekSkillFrontmatter(e)
	default:
		return c, false
	}
}

func deepSeekSkillFrontmatter(e *entry) bool {
	if e.Doc != nil {
		for _, unit := range e.Doc.Units() {
			if tree, ok := unit.Tree.(parse.JSONTree); ok && unit.Origin == "frontmatter" {
				name, named := tree.Root.Get("name").Text()
				description, described := tree.Root.Get("description").Text()

				return named && name != "" && described && description != ""
			}
		}
	}

	return false
}

func deepSeekStandalonePatch(e *entry) bool {
	root := capturedJSON(e)
	return root != nil && root.Kind == jsonconfig.KindArray
}

func (p *plugin) deepSeekWorkspace() {
	processed := map[string]bool{}

	names := p.ns.names
	if p.root != "." {
		names = p.ns.descendants(p.root)
	}

	for _, name := range names {
		if !p.b.step() {
			return
		}

		if root, ok := artifact.DeepSeekSkillRoot(name, p.b.r.RequestedHost); ok && root == p.root {
			e := p.ns.entries[name]
			p.component(report.ComponentSkill, e, p.activation, selectionHostDefault, whole(e), "skill")

			continue
		}

		if path.Dir(name) != p.root {
			continue
		}

		e := p.ns.entries[name]
		switch {
		case artifact.DeepSeekSettingsName(name, p.b.r.RequestedHost):
			p.component(componentHostConfig, e, p.activation, basisConfiguration, whole(e), "settings")
		case artifact.DeepSeekCordisName(name) || name == p.manifest.name && artifact.DeepSeekYAMLName(name) && deepSeekStandalonePatch(e):
			p.deepSeekCordis(e)

			processed[name] = true
		case name == p.manifest.name && path.Ext(name) == ".md" && deepSeekSkillFrontmatter(e):
			p.component(report.ComponentSkill, e, p.activation, selectionHostDefault, whole(e), "skill")
		}
	}

	if e := p.entry("package.json"); agentconfig.DeepSeekManifest(capturedJSON(e)) {
		p.deepSeekManifest(e, processed)
	}
}

func (p *plugin) deepSeekManifest(e *entry, processed map[string]bool) {
	n := p.object(e)
	p.component(componentHostConfig, e, p.activation, basisManifest, whole(e), "manifest")

	if bundles := agentconfig.DeepSeekBundles(n); bundles != nil {
		for i, bundle := range bundles.Elements {
			if !p.b.step() {
				return
			}

			if _, ok := bundle.Text(); ok {
				s := ref(e, bundle.Span)
				id := p.component(componentExtension, e, p.activation, basisManifest, s, fmt.Sprintf("profile-bundle:%d", i))
				p.reference(id, referenceKindDependency, report.ReferenceUnresolved, reasonExternalDependencyNotMaterialized, "", s)
			}
		}
	}

	for _, patch := range pathValues(agentconfig.DeepSeekPatchDeclarations(n)) {
		if !p.b.step() {
			return
		}

		raw, _ := patch.Text()
		name, reason := artifactpath.Reference(raw, false)

		s := ref(e, patch.Span)
		if reason != "" || !artifact.DeepSeekYAMLName(name) {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
			continue
		}

		target := p.entry(name)
		if target == nil || target.Doc == nil {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, report.ReferenceReasonComponentNotCaptured, "", s)
			continue
		}

		id := p.component(componentHostConfig, target, p.activation, basisManifest, whole(target), "bundle-patch")
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceResolved, reasonCapturedFile, id, s)

		if !processed[target.name] {
			*target.Doc = target.Doc.WithCordisYAML(p.b.ctx)
			p.deepSeekCordis(target)
			processed[target.name] = true
		}
	}
}

func (p *plugin) deepSeekCordis(e *entry) {
	root := p.deepSeekYAMLRoot(e)
	if root == nil || root.Kind == jsonconfig.KindNull {
		return
	}

	parent := ""
	ordinal := 0

	for row := range agentconfig.DeepSeekRows(root) {
		if !p.b.step() {
			return
		}

		activation := p.activation
		if row.State == "disabled" {
			activation = activationInactiveForProfile
		}

		switch row.Kind {
		case agentconfig.DeepSeekInvalid:
			p.issue("plugin_cordis_entry_invalid", e.Meta.Path, formatInvalid)
		case agentconfig.DeepSeekInclude:
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, "cordis_include_unverified", "", ref(e, row.Node.Span))
		case agentconfig.DeepSeekMCP:
			if parent == "" {
				parent = p.component(report.ComponentMCPConfig, e, p.activation, basisConfiguration, whole(e), "cordis-mcp")
			}

			p.serverEntry(e, row.Node, report.ComponentMCPConfig, parent, activation, ordinal)
			ordinal++
		case agentconfig.DeepSeekPlugin:
			p.component(componentExtension, e, activation, basisConfiguration, ref(e, row.Node.Span), row.Key)
		}
	}
}

func (p *plugin) deepSeekYAMLRoot(e *entry) *jsonconfig.Node {
	if e.Doc != nil {
		for _, unit := range e.Doc.Units() {
			if unit.Origin == "file" && unit.Language == language.YAML {
				return p.configRoot(e, unit)
			}
		}
	}

	p.issue("plugin_yaml_unavailable", e.Meta.Path, report.OutcomePartial)

	return nil
}

func deepSeekDynamicCommand(n *jsonconfig.Node) bool {
	if n.GetOrEmpty(fieldCommand).Kind == jsonconfig.KindExpression {
		return true
	}

	args := n.GetOrEmpty(fieldArgs)

	return args.Kind == jsonconfig.KindExpression || slices.ContainsFunc(args.Elements, func(arg *jsonconfig.Node) bool {
		return arg.Kind == jsonconfig.KindExpression
	})
}
