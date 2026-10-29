package scout_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/report"
)

func TestProfilesSelectChecksWithoutGrantingEgress(t *testing.T) {
	for _, name := range []scout.Profile{scout.Standard, scout.Review, scout.Custom} {
		t.Run(string(name), func(t *testing.T) {
			options := scout.DefaultOptions()
			options.Profile = name
			if name == scout.Custom {
				options.Checks = &scout.Checks{}
			}
			if options.Download != nil || options.Vulnerabilities != nil || options.Review != nil {
				t.Fatal("profile granted an external service")
			}
			scanner, err := scout.New(context.Background(), options)
			missing := !frontend.BackendFor("python").Available || !signatures.Backend().Available
			if name == scout.Review || name == scout.Standard && missing {
				if err == nil {
					if err := scanner.Close(); err != nil {
						t.Error(err)
					}
					t.Fatal("unavailable or unconsented profile accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := scanner.Close(); err != nil {
					t.Error(err)
				}
			}()
			plan := scanner.InspectionPlan()
			if plan.Name != string(name) || plan.Egress.Download || plan.Egress.SourceUpload || plan.Egress.VulnerabilityNetwork {
				t.Fatal(plan)
			}
		})
	}
}

func TestInspectionPlanFollowsEffectiveConfigAndIsImmutable(t *testing.T) {
	config := scantest.DefaultConfig()
	config.Scanner.Checks.Patterns = true
	scanner, err := scantest.New(config, t)
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.InspectionPlan()
	if plan.Name != "custom" {
		t.Fatal(plan)
	}
	plan.Checks[0].Selected = false
	result, err := scanner.ScanBytes(context.Background(), "readme.txt", []byte("plain text"))
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) || result.Run.Plan.Name != "custom" || !result.Run.Plan.Checks[0].Selected {
		t.Fatal(result.Run.Plan, err)
	}
	if result.Run.State != "complete" || result.Evaluation.Decision != "allow" {
		t.Fatal(result.Document)
	}
}

func TestMissingSelectedBackendsCannotBecomeCompleteAllow(t *testing.T) {
	options := scout.DefaultOptions()
	scanner, err := scout.New(context.Background(), options)
	if !frontend.BackendFor("python").Available || !signatures.Backend().Available {
		if err == nil {
			if err := scanner.Close(); err != nil {
				t.Error(err)
			}
			t.Fatal("required unavailable backend accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	run, err := scanner.Scan(context.Background(), scout.Reader("readme.txt", strings.NewReader("plain text")))
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) || run.State != "complete" {
		t.Fatal(err, run.State)
	}
}

func TestUnavailableEmbeddedCapabilitiesNeverAllow(t *testing.T) {
	if signatures.Backend().Available || frontend.BackendFor("python").Available {
		t.Skip("absence requires explicit reduced build")
	}
	if scanner, err := scout.New(context.Background(), scout.DefaultOptions()); err == nil {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("required unavailable engines accepted")
	}
}

func TestLegacyRuntimeConfigurationIsNotRepresentable(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[frontend.Options](), reflect.TypeFor[signatures.Options](), reflect.TypeFor[scout.Options]()} {
		for _, field := range []string{"Interpreter", "YAMLLibrary", "Library", "PythonRuntime"} {
			if _, exists := typ.FieldByName(field); exists {
				t.Fatalf("legacy runtime field %s.%s remains", typ.Name(), field)
			}
		}
	}
}

func TestAnalysisIdentityUsesSelectedProfileAndRulepack(t *testing.T) {
	for _, patterns := range []bool{false, true} {
		options := basicOptions()
		options.Checks.Patterns = patterns
		scanner := testScanner(t, options)
		run, err := scanner.Scan(context.Background(), scout.Reader("readme.txt", strings.NewReader("ordinary text")))
		if err != nil {
			t.Fatal(err)
		}
		analysis := run.Targets[0].Analysis
		if analysis.SchemaVersion != report.AnalysisSchema || analysis.EngineVersion != scout.Version() || analysis.EngineVersion != run.Engine.Version {
			t.Fatalf("analysis and run disagree: %+v %+v", analysis, run.Engine)
		}
		if analysis.Profile != string(options.Profile) || analysis.Profile != run.Plan.Name || analysis.Profile != analysis.Inspection.Name {
			t.Fatalf("profile does not describe the selected plan: %q %+v", analysis.Profile, run.Plan)
		}
		if analysis.RulepackDigest != run.Engine.RulepackDigest || !strings.HasPrefix(analysis.RulepackDigest, "sha256:") || len(analysis.RulepackDigest) != 71 {
			t.Fatalf("invalid rulepack identity: %+v", run.Engine)
		}
		data, err := json.Marshal(analysis)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"rules_version"`) || !strings.Contains(string(data), `"rulepack_digest"`) {
			t.Fatal("analysis still serializes manual rules metadata")
		}
	}
}

func TestRulepackDigestTracksChecksIndependentlyOfInput(t *testing.T) {
	identities := map[bool]string{}
	for _, patterns := range []bool{false, true} {
		options := basicOptions()
		options.Checks.Patterns = patterns
		scanner := testScanner(t, options)
		for _, text := range []string{"ordinary text", "different input"} {
			run, err := scanner.Scan(context.Background(), scout.Reader("readme.txt", strings.NewReader(text)))
			if err != nil {
				t.Fatal(err)
			}
			if previous := identities[patterns]; previous != "" && previous != run.Engine.RulepackDigest {
				t.Fatal("input bytes changed the rulepack identity")
			}
			identities[patterns] = run.Engine.RulepackDigest
		}
	}
	if identities[false] == identities[true] {
		t.Fatal("selected checks did not change the rulepack identity")
	}
}
