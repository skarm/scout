package integrations_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/distribution/integrations"
	"github.com/skarm/scout/knowledge"
)

func TestBundleLayoutsAndImportPaths(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
	}{
		{name: "agent-skill", paths: []string{"skill-inspector/SKILL.md", "skill-inspector/LICENSE"}},
		{name: "claude-code", paths: []string{".claude-plugin/plugin.json", "skills/skill-inspector/SKILL.md"}},
		{name: "codex", paths: []string{".codex-plugin/plugin.json", "skills/skill-inspector/SKILL.md"}},
		{
			name:  "pi",
			paths: []string{"package.json", "extensions/scout.ts", "extensions/lib/adapters.mjs", "extensions/lib/runner.mjs", "skills/skill-inspector/SKILL.md"},
		},
		{
			name:  "opencode",
			paths: []string{".opencode/package.json", ".opencode/tools/scout_scan.ts", ".opencode/lib/scout/adapters.mjs", ".opencode/lib/scout/runner.mjs", ".opencode/commands/scout.md", ".opencode/skills/skill-inspector/SKILL.md"},
		},
		{
			name:  "review-materials",
			paths: []string{"validation/pack.json", "validation/prompts/discovery.md", "skills/skill-inspector/SKILL.md"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := files(t, tc.name)
			for _, p := range append(tc.paths, "LICENSE", "NOTICE", "transfer-manifest.json") {
				if len(m[p]) == 0 {
					t.Fatalf("missing %s", p)
				}
			}
			for p, b := range m {
				if !fs.ValidPath(p) || strings.Contains(p, "\\") || strings.Contains(p, "testdata/") {
					t.Fatalf("invalid export: %s", p)
				}
				if strings.HasSuffix(p, ".json") {
					if !json.Valid(b) {
						t.Fatalf("invalid JSON %s", p)
					}
				}
				if strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".mjs") {
					// Resolve real local relative imports. Host SDK imports deliberately stay external.
					for line := range strings.SplitSeq(string(b), "\n") {
						for part := range strings.SplitSeq(line, "'") {
							if (strings.HasPrefix(part, "./") || strings.HasPrefix(part, "../")) && strings.HasSuffix(part, ".mjs") {
								q := path.Clean(path.Join(path.Dir(p), part))
								if len(m[q]) == 0 {
									t.Fatalf("broken import %s -> %s", p, q)
								}
							}
						}
					}
				}
				if strings.HasSuffix(p, "SKILL.md") {
					for _, ref := range []string{"review-checklist.md", "report-template.md", "command-contract.md", "provenance.md"} {
						if !bytes.Contains(b, []byte("references/"+ref)) || len(m[path.Join(path.Dir(p), "references", ref)]) == 0 {
							t.Fatalf("broken skill reference %s", ref)
						}
					}
				}
			}
		})
	}
}

func TestSkillWorkflowObligations(t *testing.T) {
	m := files(t, "agent-skill")
	skill := string(m["skill-inspector/SKILL.md"])
	check := string(m["skill-inspector/references/review-checklist.md"])
	cases := []string{"## Goal", "two independent lines", "## Operating rules", "### 1.", "### 2.", "### 3.", "### 4.", "### 5.", "### 6.", "## Score interpretation", "## Report style", "## Manual fallback", "APPROVE", "CAUTION", "REJECT", "Exit `2`", "unavailable", "Do not install", "read-only", "--checks python,yaml,toml,yara,patterns", "--format json --", "native backend", "user's language"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if !strings.Contains(skill, c) {
				t.Fatalf("missing obligation %s", c)
			}
		})
	}
	for _, c := range []string{"Purpose fit", "Permission fit", "Sensitive access", "External transmission", "Execution risk", "Persistence", "Prompt risk", "Activation/trigger scope", "Supply-chain provenance", "User control"} {
		if !strings.Contains(check, c) {
			t.Errorf("missing review dimension %s", c)
		}
	}
	for _, bad := range []string{"--no-llm", "uv tool install", "pip install -r", "npm install --", "safe_to_install = true"} {
		if strings.Contains(skill, bad) {
			t.Errorf("stale/unsafe instruction %s", bad)
		}
	}
}

func TestReviewMaterialsMatchRuntime(t *testing.T) {
	m := files(t, "review-materials")
	for _, mode := range []string{"discovery", "intent", "quality", "tool_consistency", "assessment", "proposal_assessment"} {
		p, e := knowledge.Prompt(mode)
		if e != nil {
			t.Fatal(e)
		}
		if string(m["validation/prompts/"+mode+".md"]) != p {
			t.Fatalf("runtime prompt drift: %s", mode)
		}
	}
	var x knowledge.Pack
	if e := json.Unmarshal(m["validation/pack.json"], &x); e != nil {
		t.Fatal(e)
	}
	if x.Manifest.SHA256 != knowledge.Inventory().SHA256 || len(x.Guidance) != len(knowledge.Catalog()) {
		t.Fatal("runtime guidance drift")
	}
	want, _ := json.Marshal(knowledge.Export())
	got, _ := json.Marshal(x)
	if !bytes.Equal(got, want) {
		t.Fatal("standalone export lost curated topics, sources or runtime guidance")
	}
}

func TestDeterministicZIPAndManifest(t *testing.T) {
	for _, name := range integrations.Names() {
		t.Run(name, func(t *testing.T) {
			var a, b bytes.Buffer
			if e := integrations.WriteZIP(&a, name); e != nil {
				t.Fatal(e)
			}
			if e := integrations.WriteZIP(&b, name); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("nondeterministic ZIP")
			}
			z, e := zip.NewReader(bytes.NewReader(a.Bytes()), int64(a.Len()))
			if e != nil {
				t.Fatal(e)
			}
			seen := map[string][]byte{}
			for _, f := range z.File {
				if f.Mode().Perm() != 0o644 || f.Mode()&fs.ModeSymlink != 0 {
					t.Fatal("executable/link entry")
				}
				r, e := f.Open()
				if e != nil {
					t.Fatal(e)
				}
				v, e := io.ReadAll(r)
				if err := r.Close(); err != nil {
					t.Error(err)
				}
				if e != nil {
					t.Fatal(e)
				}
				if _, ok := seen[f.Name]; ok {
					t.Fatal("duplicate")
				}
				seen[f.Name] = v
			}
			var manifest integrations.Manifest
			if e := json.Unmarshal(seen[".scout-bundle.json"], &manifest); e != nil {
				t.Fatal(e)
			}
			if len(manifest.Files) != len(seen)-1 {
				t.Fatal("unaccounted entry")
			}
			for _, f := range manifest.Files {
				sum := sha256.Sum256(seen[f.Path])
				if f.Bytes != len(seen[f.Path]) || f.SHA256 != hex.EncodeToString(sum[:]) {
					t.Fatal("digest mismatch")
				}
			}
			if manifest.Bundle != name {
				t.Fatal("identity mismatch")
			}
			var transfer struct {
				Version           string `json:"version"`
				AdaptationVersion string `json:"adaptation_version"`
			}
			if err := json.Unmarshal(seen["transfer-manifest.json"], &transfer); err != nil {
				t.Fatal(err)
			}
			if transfer.Version == "" || transfer.Version != manifest.Version {
				t.Fatalf("transfer version %q differs from bundle version %q", transfer.Version, manifest.Version)
			}
			if transfer.AdaptationVersion != "scout-reviewer-transfer-v2" {
				t.Fatal("original adaptation identity lost")
			}
		})
	}
}

func TestReturnedAssetsAreIndependent(t *testing.T) {
	a := files(t, "pi")
	a["extensions/scout.ts"][0] = '!'
	b := files(t, "pi")
	if b["extensions/scout.ts"][0] == '!' {
		t.Fatal("shared asset mutation")
	}
	n := integrations.Names()
	n[0] = "evil"
	if integrations.Names()[0] == "evil" {
		t.Fatal("shared names")
	}
}

func TestUnknownBundle(t *testing.T) {
	if _, e := integrations.Files("../pi"); e == nil {
		t.Fatal("unknown accepted")
	}
	if e := integrations.WriteZIP(io.Discard, "unknown"); e == nil {
		t.Fatal("unknown accepted")
	}
	if e := integrations.WriteZIP(nil, "pi"); e == nil {
		t.Fatal("nil writer accepted")
	}
}

func TestTransferScopeDoesNotInventUpstreamVerification(t *testing.T) {
	m := files(t, "review-materials")
	var manifest struct {
		Commit         *string `json:"upstream_commit"`
		TreeEnumerated bool    `json:"upstream_tree_enumerated"`
		Comparison     struct {
			Commit       string `json:"commit"`
			Enumerated   bool   `json:"tree_enumerated"`
			Files        int    `json:"file_count"`
			FullScanner  bool   `json:"full_scanner_executed"`
			Mode         string `json:"execution_mode"`
			Cases        int    `json:"case_count"`
			FixtureFiles int    `json:"fixture_file_count"`
			AllFixtures  bool   `json:"all_fixture_files_covered"`
			LiveLLM      bool   `json:"live_llm_executed"`
			Verification string `json:"verification"`
		} `json:"comparison_reference"`
		Entries []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Target string `json:"target"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(m["transfer-manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Commit != nil || manifest.TreeEnumerated {
		t.Fatal("unverified upstream provenance claimed")
	}
	seen := map[string]string{}
	for _, e := range manifest.Entries {
		if _, ok := seen[e.ID]; ok {
			t.Fatal("duplicate transfer entry")
		}
		seen[e.ID] = e.Status
	}
	for _, id := range []string{"SI-GOAL", "SI-BOUNDARY", "SI-WORKFLOW", "SI-DIMENSIONS", "SI-RUBRIC", "SI-SCORE", "SI-REPORT", "SI-FALLBACK", "PI-TOOL", "PI-PACKAGE", "OC-TOOL", "OC-COMMAND", "LLM-PROMPTS", "RULES-GUIDANCE"} {
		if seen[id] == "" {
			t.Fatalf("unaccounted required transfer %s", id)
		}
	}
	if manifest.Comparison.Commit == "" || !manifest.Comparison.Enumerated || manifest.Comparison.Files == 0 || !manifest.Comparison.FullScanner || manifest.Comparison.Mode != "static_only_network_denied_no_llm" || manifest.Comparison.Cases != 148 || manifest.Comparison.FixtureFiles != 52 || !manifest.Comparison.AllFixtures || manifest.Comparison.LiveLLM || manifest.Comparison.Verification != "testdata/provenance/differential-0.19.json" {
		t.Fatal("static comparison evidence missing or unsupported live execution claimed")
	}
	if seen["FULL-REPO"] != "full_fixture_static_differential_verified_partial_port" || seen["YARA-X"] != "native_acceptance_verified" {
		t.Fatal("global gaps were concealed")
	}
}

func files(t *testing.T, name string) map[string][]byte {
	t.Helper()
	f, e := integrations.Files(name)
	if e != nil {
		t.Fatal(e)
	}
	m := map[string][]byte{}
	for _, v := range f {
		m[v.Path] = v.Data
	}
	return m
}
