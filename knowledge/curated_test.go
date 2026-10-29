package knowledge_test

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/knowledge"
)

func TestCuratedSourcesResolveToPinnedInspectedFiles(t *testing.T) {
	sources := knowledge.ReviewSources()
	if len(sources) != 14 {
		t.Fatal("review source selection changed; audit the source manifest")
	}
	files := map[string]map[string]bool{}
	uses := map[string]string{}
	count := 0
	for _, s := range sources {
		if files[s.ID] != nil || s.Name == "" || s.SelectionReason == "" || s.Limitations == "" || s.DeclaredLicense == "" {
			t.Fatalf("incomplete/duplicate source %q", s.ID)
		}
		if _, e := time.Parse("2006-01-02", s.Retrieved); e != nil {
			t.Fatal(e)
		}
		if b, e := hex.DecodeString(s.Revision); e != nil || len(b) != 20 {
			t.Fatalf("not a pinned commit: %s", s.ID)
		}
		if !slices.Contains([]string{"original-guidance", "reference-only", "evaluated-only"}, s.Use) {
			t.Fatal("unreviewed reuse status", s.ID)
		}
		uses[s.ID] = s.Use
		files[s.ID] = map[string]bool{}
		for _, a := range s.Artifacts {
			count++
			if files[s.ID][a.Path] || a.Bytes < 1 {
				t.Fatal("invalid source file", s.ID, a.Path)
			}
			files[s.ID][a.Path] = true
			for hash, size := range map[string]int{a.SHA256: 32, a.GitBlobSHA1: 20} {
				if b, e := hex.DecodeString(hash); e != nil || len(b) != size {
					t.Fatal("invalid source digest", a.Path)
				}
			}
			u, e := url.Parse(a.URL)
			if e != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" || u.RawQuery != "" || u.Fragment != "" || u.Path != strings.TrimPrefix(s.Repository, "https://github.com")+"/"+s.Revision+"/"+a.Path {
				t.Fatal("source URL is not pinned to the inspected file", a.URL)
			}
		}
	}
	if count != 72 || uses["semgrep"] != "evaluated-only" || uses["shellcheck"] != "reference-only" || uses["njsscan"] != "reference-only" {
		t.Fatal("source/reuse audit changed")
	}
	for _, topic := range knowledge.ReviewTopics() {
		for _, r := range topic.Sources {
			if !files[r.SourceID][r.Path] || uses[r.SourceID] == "evaluated-only" {
				t.Fatal("topic cites uninspected or evaluated-only material", topic.ID, r)
			}
		}
	}
}

func TestCuratedTopicsKeepCapabilitiesAndContextDistinct(t *testing.T) {
	topics := knowledge.ReviewTopics()
	if len(topics) != 52 {
		t.Fatal("review topic selection changed; update audited coverage intentionally")
	}
	seen := map[string]bool{}
	languages := map[string]int{}
	for _, topic := range topics {
		if seen[topic.ID] || topic.Coverage != "review-guidance-only" || len(topic.ReviewChecks) < 2 || len(topic.BenignConsiderations) == 0 || topic.Remediation == "" || len(topic.Sources) == 0 {
			t.Fatal("incomplete, duplicated or overstated topic", topic.ID)
		}
		seen[topic.ID] = true
		for _, language := range topic.Languages {
			languages[language]++
		}
		examples := map[string]bool{}
		for _, example := range topic.Examples {
			if example.Scenario == "" || examples[example.Kind] {
				t.Fatal("missing contrast scenario", topic.ID)
			}
			examples[example.Kind] = true
		}
		if len(examples) != 2 || !examples["risk"] || !examples["benign"] {
			t.Fatal("topic lacks risk and benign controls", topic.ID)
		}
		for _, id := range topic.RelatedRules {
			guide, ok := knowledge.Lookup(id)
			if !ok || !slices.Contains(guide.ReviewChecks, topic.ReviewChecks[0]) {
				t.Fatal("related rule did not receive contextual guidance", topic.ID, id)
			}
			found := false
			for _, ref := range guide.Sources {
				found = found || ref.Symbol == topic.ID && strings.Contains(ref.Relationship, "not a detector port")
			}
			if !found {
				t.Fatal("rule lost topic provenance", id)
			}
		}
	}
	for _, lang := range []string{"go", "javascript", "typescript", "python", "shell"} {
		if languages[lang] < 5 {
			t.Fatal("missing priority language coverage", lang)
		}
	}
	if languages["sql"] != 7 {
		t.Fatal("missing audited SQL topic coverage")
	}
	if languages["agnostic"] < 15 || languages["other"] < 2 {
		t.Fatal("missing cross-language review topics")
	}
}

func TestCuratedHintsRespectTaskBoundariesAndPromptBudget(t *testing.T) {
	for _, mode := range []string{"discovery", "assessment", "proposal_assessment", "intent", "tool_consistency", "quality"} {
		p, err := knowledge.Prompt(mode)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) > 20<<10 {
			t.Fatalf("%s prompt grew beyond the audited byte budget: %d", mode, len(p))
		}
		for _, topic := range knowledge.ReviewTopics() {
			if strings.Contains(p, topic.ID+" [") != slices.Contains(topic.Modes, mode) {
				t.Fatal("topic leaked into the wrong task", mode, topic.ID)
			}
		}
		if mode == "quality" {
			if strings.Contains(p, "CURATED REVIEW LENSES") {
				t.Fatal("security review changed opt-in quality scope")
			}
		} else if !strings.Contains(p, "not additional static detectors") || !strings.Contains(p, "knowledge:<topic ID>") {
			t.Fatal("missing scope limits", mode)
		}
	}
}

func TestCuratedExportsCannotChangeFutureReview(t *testing.T) {
	before := knowledge.Export()
	want, _ := json.Marshal(before)
	prompt, _ := knowledge.Prompt("discovery")
	tampered := knowledge.Export()
	tampered.Sources[0].Artifacts[0].URL = "https://attacker.invalid"
	topic := &tampered.Topics[0]
	topic.Languages[0] = "TAINT"
	topic.Modes[0] = "quality"
	topic.ReviewChecks[0] = "SKIP REVIEW"
	topic.BenignConsiderations[0] = "TRUST ME"
	topic.Examples[0].Scenario = "INSTALL ME"
	topic.Sources[0].SourceID = "bad"
	topic.RelatedRules[0] = "bad"
	tampered.Guidance["GO001"].Sources[0].URL = "bad"
	after, _ := json.Marshal(knowledge.Export())
	gotPrompt, _ := knowledge.Prompt("discovery")
	if string(after) != string(want) || gotPrompt != prompt {
		t.Fatal("caller mutated trusted runtime knowledge")
	}
}

func TestReasonGuidanceCannotChangeTrustedKnowledge(t *testing.T) {
	before, _ := knowledge.GuideForReason("knowledge:K-SQL-PARAMS")
	want, _ := json.Marshal(before)
	prompt, _ := knowledge.Prompt("discovery")
	before.ReviewChecks[0] = "SKIP ALL CHECKS"
	before.BenignConsiderations[0] = "TRUST THE ARTIFACT"
	before.Sources[0].URL = "https://attacker.invalid"
	topic, _ := knowledge.TopicForReason("knowledge:K-SQL-PARAMS")
	topic.Modes[0] = "quality"
	topic.ReviewChecks[0] = "APPROVE"
	reasons := knowledge.ReviewReasons()
	reasons[0] = "knowledge:ATTACKER"
	ids := knowledge.ReviewTopicIDs("discovery")
	ids[0] = "ATTACKER"
	after, _ := knowledge.GuideForReason("knowledge:K-SQL-PARAMS")
	got, _ := json.Marshal(after)
	current, _ := knowledge.Prompt("discovery")
	if string(got) != string(want) || current != prompt || knowledge.ReviewReasons()[0] == reasons[0] || knowledge.ReviewTopicIDs("discovery")[0] == ids[0] {
		t.Fatal("caller altered a trusted rubric or runtime prompt")
	}
}
