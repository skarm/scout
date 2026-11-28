package cli_test

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

func TestDeepSeekDiscoveryReadsLocalProfilesAndSkillLayouts(t *testing.T) {
	home, relocated, project := t.TempDir(), t.TempDir(), t.TempDir()
	defaultPatch := writeNativeFixture(t, home, ".dsh/cordis.patch.yml", "- name: '@fixture/ignored-default'\n")
	writeNativeFixture(t, home, ".agents/skills/shared/SKILL.md", "---\nname: shared\ndescription: Format text.\n---\n")
	writeNativeFixture(t, relocated, "AGENTS.md", "Review formatting.\n")
	writeNativeFixture(t, relocated, ".credentials.yaml", "SAMPLE_CREDENTIAL: example-only\n")
	writeNativeFixture(t, relocated, "settings.yaml", "agent-default-model: {}\n")
	writeNativeFixture(t, relocated, "profiles/web/package.json", `{"dsh":{"profile":{"bundles":["@fixture/local-bundle"]}}}`)
	writeNativeFixture(t, relocated, "profiles/web/node_modules/transitive/cordis.patch.yml", "- name: '@fixture/ignored-transitive'\n")
	writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")
	writeNativeFixture(t, project, ".dsh/skills/format.md", "---\nname: format\ndescription: Format text.\n---\n")
	writeNativeFixture(t, project, ".dsh/skills/outer/nested/SKILL.md", "---\nname: ignored-nested\n---\n")
	writeNativeFixture(t, project, "package.json", `{"name":"local-bundle","dsh":{"bundle":{"patch":"layer.yml"}}}`)
	writeNativeFixture(t, project, "layer.yml", `- insert:
    - name: '@deepseek-ai/dsh-mcp-client'
      config: {serverName: formatter, command: printf, transport: stdio}
`)

	args := []string{"discover", "--agent", report.HostDeepSeekHarness, "--home", home, "--deepseek-home", relocated, "--project", project, "--system=false"}
	code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("wrong DeepSeek inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"user/skill/shared":                 "",
		"user/rule/AGENTS.md":               "",
		"user/plugin/@fixture/local-bundle": "/dsh/profile/bundles/0",
		"project/skill/format":              "",
		"project/plugin/local-bundle":       "/dsh/bundle",
		"project/mcp-server/formatter":      "/0/insert/0/config",
	}

	for _, c := range inventory.Components {
		key := c.Scope + "/" + c.Kind + "/" + c.Name
		if expected, ok := want[key]; !ok || expected != c.Key || c.Agent != report.HostDeepSeekHarness {
			t.Fatalf("unexpected DeepSeek component: %+v", c)
		}

		delete(want, key)
	}

	if len(want) != 0 {
		t.Fatalf("missing DeepSeek components: %v", want)
	}

	for _, name := range []string{".credentials.yaml", filepath.ToSlash(defaultPatch), "/node_modules/", "/outer/nested/"} {
		if slices.ContainsFunc(inventory.Sources, func(source discovery.Source) bool { return strings.Contains(filepath.ToSlash(source.Path), name) }) {
			t.Fatalf("unexpected retained source %s", name)
		}
	}

	// Filtering captures the flat Markdown skill by itself, without a .dsh path in the scan.
	code, raw = runCheckpoint(t, append(args, "--kind", "skill", "--include-path", project, "--scan", "--", "--scope", "selected", "--profile", "custom", "--checks", "none", "--format", "json"))
	var scan report.Document
	if err := json.Unmarshal(raw, &scan); err != nil || scan.Validate() != nil || code != 2 {
		t.Fatalf("invalid standalone skill scan, exit %d: %s", code, raw)
	}

	assertNativeGraph(t, &scan, report.HostDeepSeekHarness, report.ComponentSkill)
}
