package discovery

import (
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (t *tree) deepSeekShared(base string) {
	t.deepSeekSkills(path.Join(base, "skills"))
	t.geminiContext(path.Join(base, "AGENTS.md"))
}

func (t *tree) deepSeekHome(base string) {
	t.deepSeekShared(base)
	t.configWithParser(path.Join(base, artifact.DeepSeekSettings), false, jsonconfig.ParseCordisYAML)
	t.deepSeekConfig(path.Join(base, artifact.DeepSeekPatch))

	root := path.Join(base, artifact.DeepSeekProfiles)
	for _, entry := range t.entries(root) {
		if entry.Name() == "node_modules" || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		dir := path.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(dir))
		} else if entry.IsDir() {
			t.deepSeekManifest(path.Join(dir, "package.json"))
			t.deepSeekConfig(path.Join(dir, artifact.DeepSeekPatch))
		}
	}
}

func (t *tree) deepSeekSkills(root string) {
	for _, entry := range t.entries(root) {
		file := path.Join(root, entry.Name())
		if entry.Name() == ".system" && t.scope == "user" {
			continue
		}

		switch {
		case entry.Type()&os.ModeSymlink != 0:
			t.b.issue(codeSymlinkRefused, t.absolute(file))
		case entry.IsDir():
			if t.skill(file, entry.Name()) {
				t.b.target(t.absolute(file))
			}
		case entry.Type().IsRegular() && path.Ext(file) == ".md" && t.read(file, false) != nil:
			t.component("skill", strings.TrimSuffix(entry.Name(), ".md"), file, file, "", "unknown")
		}
	}
}

func (t *tree) deepSeekConfig(file string) { t.deepSeekCordis(file, false) }

func (t *tree) deepSeekCordis(file string, required bool) {
	data := t.read(file, required)
	if data == nil {
		return
	}

	root, err := jsonconfig.ParseCordisYAML(t.b.ctx, string(data))
	if err != nil {
		t.b.issue(codeInvalidConfig, t.absolute(file))
		return
	}

	if root.Kind == jsonconfig.KindNull {
		return
	}

	for row := range agentconfig.DeepSeekRows(root) {
		if !t.b.step(t.absolute(file)) {
			return
		}

		switch row.Kind {
		case agentconfig.DeepSeekInclude:
			t.b.issue("unresolved_cordis_include", t.absolute(file))
		case agentconfig.DeepSeekInvalid:
			t.b.issue(codeInvalidConfig, t.absolute(file))
		default:
			t.component(row.Kind, row.Name, file, file, row.Key, row.State)
		}
	}
}

func (t *tree) deepSeekManifest(file string) {
	var root *jsonconfig.Node

	t.readIf(file, false, func(data []byte) bool {
		root, _ = jsonconfig.Parse(t.b.ctx, string(data))
		return agentconfig.DeepSeekManifest(root)
	})

	if !agentconfig.DeepSeekManifest(root) {
		return
	}

	t.deepSeekProfileBundles(file, agentconfig.DeepSeekBundles(root))
	t.deepSeekBundle(file, root)
}

func (t *tree) deepSeekProfileBundles(file string, bundles *jsonconfig.Node) {
	if bundles == nil {
		return
	}

	if bundles.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	for i, node := range bundles.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if name, ok := node.Text(); ok && strings.TrimSpace(name) != "" {
			t.component(agentconfig.DeepSeekPlugin, name, file, file, "/dsh/profile/bundles/"+strconv.Itoa(i), "unknown")
		} else {
			t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		}
	}
}

func (t *tree) deepSeekBundle(file string, root *jsonconfig.Node) {
	patch := agentconfig.DeepSeekPatchDeclarations(root)
	if patch == nil {
		return
	}

	if name, ok := root.Get(fieldName).Text(); ok && strings.TrimSpace(name) != "" {
		t.component(agentconfig.DeepSeekPlugin, name, file, file, "/dsh/bundle", "unknown")
	}

	patches := []*jsonconfig.Node{patch}
	if patch.Kind == jsonconfig.KindArray {
		patches = patch.Elements
	}

	for _, node := range patches {
		if !t.b.step(t.absolute(file)) {
			return
		}

		raw, _ := node.Text()

		name, reason := artifactpath.Reference(raw, false)
		if reason != "" || !artifact.DeepSeekYAMLName(name) {
			t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
			continue
		}

		t.deepSeekCordis(path.Join(path.Dir(file), name), true)
	}
}
