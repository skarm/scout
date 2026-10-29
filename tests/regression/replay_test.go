package scout_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/dev/provenance"
	"github.com/skarm/scout/internal/dev/replay"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/report"
)

// These exact captured inputs account for the four finding additions between
// the saved 0.25 baseline and the intermediate 0.26 replay. They are scanned as
// data only; no Python or shell payload is executed.
func TestCapturedLocalWriteAndRemovalEvidence(t *testing.T) {
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{
		Python:   frontend.BackendFor("python").Available,
		Patterns: true,
	}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, fixture := range []struct {
		name, recordID, path, text, rule, fileSHA256 string
		start, end                                   int
	}{
		{
			name:       "local-file-environment",
			recordID:   "0ebe21fdbf91a29b988179926cd2ccf428a08133cb3bb5dd871b260afc09e8f0",
			path:       "script.py",
			text:       "import os, urllib.request\nopen(\"local.txt\", \"w\").write(os.getenv(\"KEY\"))\n",
			rule:       "PY-TT1",
			fileSHA256: "76bb3ce3bb835019e2032e4f1da48ae44ab84bf397f02b060a2d2239b6ee867c",
			start:      26,
			end:        72,
		},
		{
			name:       "quoted-absolute-command",
			recordID:   "cb66b309f497ef85e92f4bd8a73770aa3083cdb961c81366af41ef244062eaa1",
			path:       "cleanup.sh",
			text:       `"/bin/rm" -rf *`,
			rule:       "NV-TM1",
			fileSHA256: "2499d2bcf966d95b769f0e8f83911431199ce6c2634924d72c5d65cfdb735bca",
			start:      0,
			end:        15,
		},
		{
			name:       "quoted-separator-del",
			recordID:   "dfc45630d17e4a9e82754e89c4ee39f29afe93e268d8e1a1adf1720fc6760342",
			path:       "cleanup.sh",
			text:       "del 'harmless;still' -rf /",
			rule:       "NV-TM1",
			fileSHA256: "cddb7aaa4b49e4ff6a9335ca9722d0c0d2338faace4ebb15d6a961bc28da6830",
			start:      0,
			end:        26,
		},
		{
			name:       "quoted-separator-erase",
			recordID:   "d22f40122d3e75c8ab5bd8a5f9333791076a76a67cf6820f76e877c9128df315",
			path:       "cleanup.sh",
			text:       "erase 'harmless;still' -rf /",
			rule:       "NV-TM1",
			fileSHA256: "fcf4b9079744ba53da67a569525220617f8901e4edef732e9ea8bbe8f0b32b96",
			start:      0,
			end:        28,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if fixture.rule == "PY-TT1" && !frontend.BackendFor("python").Available {
				t.Skip("native Python grammar required")
			}
			fileSum := sha256.Sum256([]byte(fixture.text))
			if hex.EncodeToString(fileSum[:]) != fixture.fileSHA256 {
				t.Fatalf("captured input bytes changed for record %s", fixture.recordID)
			}
			run, err := scanner.Scan(context.Background(), scout.Reader(fixture.path, strings.NewReader(fixture.text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatalf("targets=%d", len(run.Targets))
			}
			var matches []report.Finding
			for _, finding := range run.Targets[0].Analysis.Findings {
				if finding.RuleID == fixture.rule {
					matches = append(matches, finding)
				}
				if fixture.rule == "PY-TT1" && finding.RuleID == "PY-TT3" {
					t.Fatal("local file write was classified as network exfiltration")
				}
			}
			if len(matches) != 1 {
				t.Fatalf("record %s: %s findings=%d", fixture.recordID, fixture.rule, len(matches))
			}
			finding := matches[0]
			if finding.Location.ByteStart != fixture.start || finding.Location.ByteEnd != fixture.end {
				t.Fatalf("record %s: finding evidence range changed", fixture.recordID)
			}
			if fixture.rule == "PY-TT1" {
				if len(finding.Trace) != 2 || finding.Trace[0].Role != "source" || finding.Trace[0].Location.ByteStart != 55 || finding.Trace[0].Location.ByteEnd != 71 || finding.Trace[1].Role != "sink" || finding.Trace[1].Location != finding.Location {
					t.Fatal("environment-to-file trace lost its exact source or sink")
				}
			}
			proofs := append([]report.TraceStep{{Location: finding.Location, Evidence: finding.Evidence}}, finding.Trace...)
			for _, proof := range proofs {
				location := proof.Location
				if location.Path != fixture.path || location.Coordinates != "text" || location.Structure != "source-file" || location.ByteStart < 0 || location.ByteStart >= location.ByteEnd || location.ByteEnd > len(fixture.text) {
					t.Fatalf("record %s: invalid physical source location", fixture.recordID)
				}
				spanSum := sha256.Sum256([]byte(fixture.text[location.ByteStart:location.ByteEnd]))
				if proof.Evidence.FileSHA256 != fixture.fileSHA256 || proof.Evidence.SpanSHA256 != hex.EncodeToString(spanSum[:]) {
					t.Fatalf("record %s: evidence does not hash captured source bytes", fixture.recordID)
				}
			}
		})
	}
}

// The upstream cases expected syntax-only AST7 observations for variable keys.
// Captured literal values now distinguish a known execution handle from a known
// harmless attribute, using the same value model as the rest of the evaluator.
func TestCapturedReflectionKeyEvidence(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native Python grammar required")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, fixture := range []struct {
		name, recordID, text, fileSHA256 string
		start, end                       int
	}{
		{
			name:       "module-dict-setdefault",
			recordID:   "51ba48f60b03305771166b208669d4066e3dd3859fd8607a8205996fe6a8a149",
			text:       "import os as o\nkey = 'system'\nhandle = o.__dict__.setdefault(key)",
			fileSHA256: "1ea2be3be755a61edfd419ecb7d6e328b4f59e95863ff55e895dd3527f91f301",
			start:      39,
			end:        65,
		},
		{
			name: "module-dict-pop", recordID: "672210057fcd3046ad089d1046ee6744295d9ca771ec3854c33df18b86d40ed3",
			text:       "import os as o\nkey = 'system'\nhandle = o.__dict__.pop(key)",
			fileSHA256: "fb98962f2ecb88fa657b7e961a8c9bd151234107e77600cc6c52f01ed99e8de6", start: 39, end: 58,
		},
		{
			name: "module-dict-get", recordID: "876c731dec44d367ad116491e5767c2be4ed457b49ca933f9a4a7281f1b3257d",
			text:       "import os as o\nkey = 'system'\nhandle = o.__dict__.get(key)",
			fileSHA256: "4e28f3a482b3b95fb280954d0c12105417ce31253b2a84ecec0a42fc9bc987b4", start: 39, end: 58,
		},
		{
			name: "module-dict-subscript", recordID: "93f1cb884cf0c2789dae370f0e98fa23d29e52ecb8ec104464d8c06961904b95",
			text:       "import os as o\nkey = 'system'\nhandle = o.__dict__[key]",
			fileSHA256: "77917e60c1a459c823e6a0fd1708f2848f827735b48eb05efdd4a48a0af9751a", start: 39, end: 54,
		},
		{
			name:       "known-harmless-getattr",
			recordID:   "d3cfeea0b60ec4b702e101341fc3a7d66c6005f1d620b208bba111c18b61213d",
			text:       "attr = 'secret'\nval = getattr(obj, attr)",
			fileSHA256: "fb87174b86df005be5ee875a3acc34bcf089dcd445a4dc24a1682d72592376d5",
			start:      0,
			end:        0,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			fileSum := sha256.Sum256([]byte(fixture.text))
			if hex.EncodeToString(fileSum[:]) != fixture.fileSHA256 {
				t.Fatalf("captured input bytes changed for record %s", fixture.recordID)
			}
			run, err := scanner.Scan(context.Background(), scout.Reader("script.py", strings.NewReader(fixture.text)))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatalf("targets=%d", len(run.Targets))
			}
			var handles []report.Finding
			for _, finding := range run.Targets[0].Analysis.Findings {
				if finding.RuleID == "PY-AST7" {
					t.Fatal("known captured attribute name was classified as dynamic")
				}
				if finding.RuleID == "PY-AST9" {
					handles = append(handles, finding)
				}
			}
			want := 0
			if fixture.end > fixture.start {
				want = 1
			}
			if len(handles) != want {
				t.Fatalf("record %s: reflective execution handles=%d, want %d", fixture.recordID, len(handles), want)
			}
			for _, finding := range handles {
				location := finding.Location
				if location.Path != "script.py" || location.Coordinates != "text" || location.Structure != "source-file" || location.ByteStart != fixture.start || location.ByteEnd != fixture.end {
					t.Fatalf("record %s: reflective handle evidence range changed", fixture.recordID)
				}
				spanSum := sha256.Sum256([]byte(fixture.text[fixture.start:fixture.end]))
				if finding.Evidence.FileSHA256 != fixture.fileSHA256 || finding.Evidence.SpanSHA256 != hex.EncodeToString(spanSum[:]) {
					t.Fatalf("record %s: evidence does not hash captured source bytes", fixture.recordID)
				}
			}
		})
	}
}

func TestProductionReplayObservationChanges(t *testing.T) {
	var corpus struct {
		Cases []struct {
			ID    string `json:"id"`
			Files []struct {
				Name, Data string
				Executable bool
			} `json:"files"`
			Expected       []provenance.Observation `json:"expected"`
			ForbiddenRules []string                 `json:"forbidden_rules"`
		}
	}
	raw, err := os.ReadFile("../../testdata/production-replay/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 10 {
		t.Fatal("capture observation inventory changed")
	}
	opts := scout.DefaultOptions()
	opts.Profile = scout.Custom
	opts.Checks = &scout.Checks{Patterns: true}
	scanner, err := scout.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scanner.Close() })
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			for _, expected := range tc.Expected {
				if strings.HasPrefix(expected.RuleID, "JS") && !scriptsyntax.Available() {
					t.Skip("native JS/TS checks are independently verified by full build")
				}
			}
			root := t.TempDir()
			for _, file := range tc.Files {
				if !filepath.IsLocal(file.Name) {
					t.Fatal("fixture path is not local")
				}
				data, err := base64.StdEncoding.DecodeString(file.Data)
				if err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(root, filepath.FromSlash(file.Name))
				if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			run, err := scanner.Scan(context.Background(), scout.Path(root))
			if err != nil && !errors.Is(err, scout.ErrIncomplete) {
				t.Fatal(err)
			}
			if len(run.Targets) != 1 {
				t.Fatal("capture target lost")
			}
			observed := map[provenance.Observation]bool{}
			for _, finding := range run.Targets[0].Analysis.Findings {
				observed[provenance.Observation{
					RuleID: finding.RuleID,
					Path:   finding.Location.Path,
					Start:  finding.Location.ByteStart,
					End:    finding.Location.ByteEnd,
				}] = true
				for _, forbidden := range tc.ForbiddenRules {
					if finding.RuleID == forbidden {
						t.Fatalf("non-string eval acquired a code execution signal: %s", forbidden)
					}
				}
			}
			for _, expected := range tc.Expected {
				if !observed[expected] {
					t.Errorf("source-bound observation lost: %+v", expected)
				}
			}
		})
	}
}

// Optional developer entrypoint delegates to the same bounded replay used by
// scout-dev. Captures pass through the public Scanner, never an engine bypass.
func TestReplayCapturedUpstreamSuite(t *testing.T) {
	input, output := os.Getenv("SCOUT_SUITE_INPUT"), os.Getenv("SCOUT_SUITE_OUTPUT")
	if input == "" && output == "" {
		t.Skip("developer-only captured suite replay")
	}
	if input == "" || output == "" {
		t.Fatal("both replay paths required")
	}
	in, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := in.Close(); err != nil {
			t.Error(err)
		}
	}()
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	}()
	workers, seconds := 6, 5
	if value := os.Getenv("SCOUT_SUITE_WORKERS"); value != "" {
		workers, err = strconv.Atoi(value)
		if err != nil || workers < 1 || workers > 8 {
			t.Fatal("invalid replay workers")
		}
	}
	if value := os.Getenv("SCOUT_SUITE_SECONDS"); value != "" {
		seconds, err = strconv.Atoi(value)
		if err != nil || seconds < 1 || seconds > 60 {
			t.Fatal("invalid replay deadline")
		}
	}
	scanner, err := scout.New(context.Background(), scout.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := replay.Run(context.Background(), scanner, in, out, replay.Options{
		Workers: workers,
		Timeout: time.Duration(seconds) * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
}
