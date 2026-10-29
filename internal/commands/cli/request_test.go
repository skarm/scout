//nolint:testpackage // Exercises private implementation details and package fixtures.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout"
	configfile "github.com/skarm/scout/internal/commands/cli/config"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/osv"
)

func TestConfigValidationReturnsThePreparedInspectionWithoutTargets(t *testing.T) {
	args := append([]string{"config", "validate"}, reducedCommandFlags()...)
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, &stderr)
	}
	var plan struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil || plan.Name != "custom" {
		t.Fatalf("invalid prepared inspection: %s %v", &stdout, err)
	}
	for _, extra := range [][]string{{"unexpected"}, {"--fail-on", "unknown"}, {"--baseline", filepath.Join(t.TempDir(), "missing")}} {
		stdout.Reset()
		stderr.Reset()
		if code := Run(context.Background(), append(append([]string{}, args...), extra...), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("invalid config request produced success: %d %s", code, &stdout)
		}
	}
}

func TestMCPArgumentsPreserveTransportIdentityAndTargetGrants(t *testing.T) {
	token := strings.Repeat("t", 32)
	t.Setenv("SCOUT_CLI_TEST_TOKEN", token)
	base := reducedCommandFlags()
	args := append(append([]string{}, base...), "--target", "candidate="+t.TempDir())
	invocation, err := parseMCPInvocation(context.Background(), args, io.Discard)
	if err != nil || invocation.transport != "stdio" || len(invocation.options.Targets) != 1 {
		t.Fatalf("stdio grants lost: %+v %v", invocation, err)
	}
	httpArgs := append(append([]string{}, base...), "--transport", "http", "--listen", "127.0.0.1:0", "--auth-token-env", "SCOUT_CLI_TEST_TOKEN", "--origin", "https://review.example")
	invocation, err = parseMCPInvocation(context.Background(), httpArgs, io.Discard)
	if err != nil || invocation.options.HTTPToken != token || len(invocation.options.AllowedOrigins) != 1 {
		t.Fatalf("HTTP invocation lost explicit configuration: %+v %v", invocation, err)
	}
	for _, controls := range [][]string{{"--transport", "http", "--listen", "0.0.0.0:8000"}, {"--transport", "http"}, {"--transport", "http", "--auth-token-env", "SCOUT_MISSING_TOKEN"}, {"--transport", "unknown"}, {"--origin", "https://review.example"}} {
		_, err := parseMCPInvocation(context.Background(), append(append([]string{}, base...), controls...), io.Discard)
		if err == nil {
			t.Fatalf("invalid transport controls accepted: %v", controls)
		}
	}
	if code := serveMCP(context.Background(), base, io.NopCloser(strings.NewReader("")), io.Discard, io.Discard); code != 0 {
		t.Fatalf("clean stdio EOF was not successful: %d", code)
	}
}

func TestRemoteTargetPinsOverlayOnlyTheExplicitInvocationValues(t *testing.T) {
	address := "https://example.invalid/candidate.zip"
	configured := scout.RemotePin{Revision: strings.Repeat("a", 40), SHA256: strings.Repeat("b", 64)}
	r := request{
		settings: configfile.DefaultSettings(),
		targets:  []string{address, "local"},
		revision: strings.Repeat("c", 40),
		sha256:   strings.Repeat("d", 64),
	}
	r.settings.RemotePins = map[string]scout.RemotePin{address: configured}
	targets, err := r.scanTargets(nil)
	expected, _ := scout.Remote(address, scout.RemotePin{Revision: r.revision, SHA256: r.sha256})
	if err != nil || len(targets) != 2 || !reflect.DeepEqual(targets[0], expected) || !targets[1].IsLocal() {
		t.Fatalf("target overlay changed: %v %v", targets, err)
	}
	if r.settings.RemotePins[address] != configured {
		t.Fatal("invocation modified the configured pin")
	}
}

func TestTrustedServiceFilesAreLoadedOnlyIntoTheirConfiguredServices(t *testing.T) {
	dir := t.TempDir()
	rules, cache := filepath.Join(dir, "extra.yar"), filepath.Join(dir, "cache.json")
	if err := os.WriteFile(rules, []byte("trusted rules"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("trusted cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := request{settings: configfile.DefaultSettings()}
	r.settings.ExtraRulesPath, r.settings.OSVCachePath = rules, cache
	options := osv.DefaultOptions()
	r.settings.Scanner.Vulnerabilities = &options
	if err := r.loadTrustedServices(nil); err != nil {
		t.Fatal(err)
	}
	if string(r.settings.Scanner.Signatures.ExtraRules) != "trusted rules" || string(r.settings.Scanner.Vulnerabilities.Offline) != "trusted cache" {
		t.Fatal("trusted services did not receive their own bytes")
	}
	r.settings.Scanner.Vulnerabilities = nil
	if err := r.loadTrustedServices(nil); err == nil {
		t.Fatal("cache was accepted without a vulnerability service")
	}
}

func TestStdinTargetsRequireOneExplicitNameAndNoPositionalInputs(t *testing.T) {
	r := request{input: "-", name: "candidate.md"}
	input := strings.NewReader("inert source")
	targets, err := r.scanTargets(input)
	if err != nil || len(targets) != 1 || targets[0].Label() != "candidate.md" || targets[0].IsLocal() {
		t.Fatalf("stdin identity changed: %v %v", targets, err)
	}
	for _, invalid := range []request{{input: "file", name: "candidate.md"}, {input: "-"}, {
		input:   "-",
		name:    "candidate.md",
		targets: []string{"other"},
	}, {name: "candidate.md"}, {}} {
		if _, err := invalid.scanTargets(input); err == nil {
			t.Fatal("ambiguous stdin or empty target request accepted")
		}
	}
}

func TestTrustedConfigurationCannotComeFromAnySelectedInput(t *testing.T) {
	input := t.TempDir()
	inside := filepath.Join(input, "config.json")
	if err := os.WriteFile(inside, []byte("operator bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{inside, input} {
		if _, err := readTrusted(inside, []string{target}, 100); err == nil {
			t.Fatal("target supplied trusted configuration")
		}
	}
	outside := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(outside, []byte("operator bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readTrusted(outside, []string{input}, 100)
	if err != nil || string(data) != "operator bytes" {
		t.Fatal("separate operator configuration was rejected")
	}
}

func TestMCPBoundaryFailuresDoNotProduceSuccessfulProtocolOutput(t *testing.T) {
	for _, flags := range [][]string{{"--unknown"}, {"--fail-on", "unknown"}, {"--workers", "0"}, {"--max-concurrent", "0"}} {
		var stdout, stderr bytes.Buffer
		args := append(reducedCommandFlags(), flags...)
		code := serveMCP(context.Background(), args, io.NopCloser(strings.NewReader("")), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("invalid MCP request succeeded: flags=%v code=%d stdout=%s", flags, code, &stdout)
		}
	}
	if code := serveMCP(context.Background(), reducedCommandFlags(), brokenMCPInput{}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("stdio read failure reported success: %d", code)
	}
}

func TestArgvParsingIsPassiveAndRetainsExplicitFalse(t *testing.T) {
	patch, err := parseArgv("scan", []string{"--config", "/missing/operator.json", "--semantic=false", "--python-ast=false", "--workers", "3", "--report", "json=first.json", "--report", "sarif=second.sarif", "--", "input"}, io.Discard, nil)
	if err != nil {
		t.Fatalf("argv parsing tried to resolve operator inputs: %v", err)
	}
	if !patch.present["semantic"] || !patch.present["python-ast"] || patch.semantic || patch.values.settings.Scanner.Checks.Python || patch.values.settings.Scanner.Concurrency.Workers != 3 || len(patch.values.reports) != 2 {
		t.Fatal("typed argv patch lost explicit false, numeric value, or repeated output")
	}
}

func TestFinalResolveDisablesConfiguredReviewBeforeCredentialAccess(t *testing.T) {
	patch, err := parseArgv("scan", []string{"--semantic=false", "--profile", "basic", "--", "input"}, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := configfile.Parse([]byte(`{"schema":"scout.config/v1","profile":"review","review":{"provider":"chat-completions","endpoint":"https://review.invalid/v1/chat/completions","model":"configured","key_env":"EXPLICIT_REVIEW_KEY"}}`), configfile.Grants{})
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	r, err := patch.resolve(settings, func(string) (string, bool) { lookups++; return "", false })
	if err != nil || lookups != 0 || r.settings.Scanner.Review != nil || r.settings.Reviewer != nil || r.settings.Scanner.Profile != scout.Custom {
		t.Fatalf("disabled review resolved credentials or retained service: %d %v", lookups, err)
	}
}

func TestFinalResolveChangesOnlyExplicitServiceFields(t *testing.T) {
	patch, err := parseArgv("scan", []string{"--allow-source-upload", "--allow-download", "--llm-max-requests", "2", "--download-timeout", "11s", "--", "input"}, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := configfile.Parse([]byte(`{"schema":"scout.config/v1","profile":"custom","checks":{"patterns":false,"python":false,"yaml":false,"toml":false,"yara":false},"download":{"timeout":"17s","allow_loopback":true},"review":{"provider":"chat-completions","endpoint":"https://review.invalid/v1/chat/completions","model":"configured","key_env":"EXPLICIT_REVIEW_KEY","max_input_bytes":65536}}`), patch.values.grants)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	r, err := patch.resolve(settings, func(name string) (string, bool) { names = append(names, name); return "operator-secret", true })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "EXPLICIT_REVIEW_KEY" || r.settings.Reviewer.Provider.Model != "configured" || r.settings.Reviewer.Settings.MaxRequests != 2 || r.settings.Reviewer.Settings.MaxInputBytes != 65536 || !r.settings.Scanner.Download.AllowLoopback || r.settings.Scanner.Download.Timeout.String() != "11s" {
		t.Fatalf("final service resolution lost configured siblings or credential identity: %+v %v", r.settings.Reviewer, names)
	}
}

func TestFinalResolveRequiresDownloadGrantForEveryControl(t *testing.T) {
	for _, control := range []struct {
		name string
		args []string
	}{
		{name: "revision", args: []string{"--revision", strings.Repeat("a", 40)}},
		{name: "hash", args: []string{"--download-sha256", strings.Repeat("a", 64)}},
		{name: "loopback", args: []string{"--download-allow-loopback"}},
	} {
		for _, grant := range []string{"", "false", "true"} {
			t.Run(control.name+"/grant="+grant, func(t *testing.T) {
				args := append([]string(nil), control.args...)
				if grant != "" {
					args = append(args, "--allow-download="+grant)
				}
				patch, err := parseArgv("scan", append(args, "--", "input"), io.Discard, nil)
				if err != nil {
					t.Fatal(err)
				}
				lookups := 0
				r, err := patch.resolve(configfile.DefaultSettings(), func(string) (string, bool) { lookups++; return "", false })
				if lookups != 0 {
					t.Fatal("download controls resolved unrelated credentials")
				}
				if grant != "true" {
					if err == nil || !strings.Contains(err.Error(), "download options require --allow-download") {
						t.Fatalf("control without download consent was admitted: %v", err)
					}
					return
				}
				if err != nil || r.settings.Scanner.Download == nil || !r.settings.Scanner.Download.Enabled || r.settings.Scanner.Review != nil || r.settings.Scanner.Vulnerabilities != nil {
					t.Fatalf("explicit download grant failed or enabled unrelated services: %v", err)
				}
			})
		}
	}
	for _, args := range [][]string{
		{"--download-allow-loopback=false"},
		{"--allow-download=false", "--download-allow-loopback=false"},
	} {
		patch, err := parseArgv("scan", append(args, "--", "input"), io.Discard, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := patch.resolve(configfile.DefaultSettings(), func(string) (string, bool) { t.Fatal("unexpected credential lookup"); return "", false })
		if err != nil || r.settings.Scanner.Download != nil {
			t.Fatalf("explicit false loopback control granted download or failed: %v", err)
		}
	}
}

func TestNamedProfilesReplaceConfiguredCustomChecks(t *testing.T) {
	config := filepath.Join(t.TempDir(), "operator.json")
	if err := os.WriteFile(config, []byte(`{"schema":"scout.config/v1","profile":"custom","checks":{"patterns":false,"python":false,"yaml":false,"toml":false,"yara":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"standard", "extended", "review", "semantic"} {
		t.Run(profile, func(t *testing.T) {
			args := []string{"--config", config, "--profile", profile}
			if profile == "review" || profile == "semantic" {
				args = append(args, "--semantic", "--allow-source-upload", "--llm-provider", "chat-completions", "--llm-endpoint", "https://example.invalid/review", "--llm-model", "fixture")
			}
			r, err := parseRequest("scan", append(args, "--", "inert.txt"), io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if r.settings.Scanner.Checks != nil {
				t.Fatalf("named profile retained custom checks: %+v", r.settings.Scanner.Checks)
			}
			if frontend.BackendFor("python").Available && signatures.Backend().Available {
				scanner, err := scout.New(context.Background(), r.settings.Scanner)
				if err != nil {
					t.Fatal(err)
				}
				_ = scanner.Close()
			}
		})
	}
	for _, flag := range []string{"--python-ast=false", "--yaml-parser=false", "--toml-parser=false", "--yara=false", "--skillspector-patterns=false"} {
		if _, err := parseRequest("scan", []string{"--config", config, "--profile", "standard", flag, "--", "inert.txt"}, io.Discard); err == nil || !strings.Contains(err.Error(), "named profiles") {
			t.Fatalf("named profile accepted explicit disabled check %s: %v", flag, err)
		}
	}
	for _, flag := range []string{"--python-ast=true", "--yaml-parser=true"} {
		r, err := parseRequest("scan", []string{"--config", config, "--profile", "standard", flag, "--", "inert.txt"}, io.Discard)
		if err != nil || r.settings.Scanner.Profile != scout.Standard || r.settings.Scanner.Checks != nil {
			t.Fatalf("enabled check %s inherited disabled config siblings: %+v %v", flag, r.settings.Scanner, err)
		}
	}
	r, err := parseRequest("scan", []string{"--config", config, "--profile", "basic", "--python-ast=true", "--", "inert.txt"}, io.Discard)
	if err != nil || r.settings.Scanner.Profile != scout.Custom || r.settings.Scanner.Checks == nil || *r.settings.Scanner.Checks != (scout.Checks{Python: true}) {
		t.Fatalf("legacy basic alias lost its explicit check patch: %+v %v", r.settings.Scanner.Checks, err)
	}
}

func TestBasicAliasPreservesExplicitChecks(t *testing.T) {
	r, err := parseRequest("scan", []string{"--profile", "basic", "--skillspector-patterns", "target"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if r.settings.Scanner.Checks == nil || !r.settings.Scanner.Checks.Patterns || r.settings.Scanner.Checks.Python {
		t.Fatal("explicit adapted patterns discarded")
	}
}

func TestConfiguredReviewerLimitsKeepProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scout.json")
	if err := os.WriteFile(path, []byte(`{"schema":"scout.config/v1","profile":"custom","checks":{"python":false,"yaml":false,"toml":false,"yara":false},"review":{"provider":"chat-completions","endpoint":"https://example.invalid/v1/chat/completions","model":"test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := parseRequest("scan", []string{"--config", path, "--allow-source-upload", "--semantic", "--llm-max-requests", "1", "target"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if r.settings.Scanner.Review == nil || r.settings.Scanner.Review.Settings.MaxRequests != 1 || r.settings.Scanner.Review.Provider.Identity().Model != "test" {
		t.Fatal("configured reviewer lost")
	}
}

func TestBedrockCLIUsesExplicitCredentials(t *testing.T) {
	t.Setenv("SCOUT_TEST_ACCESS", "TESTACCESS123")
	t.Setenv("SCOUT_TEST_SECRET", "fixture-secret-only")
	t.Setenv("SCOUT_TEST_SESSION", "fixture-session-only")
	common := []string{"--profile", "basic", "--semantic", "--allow-source-upload", "--llm-provider", "bedrock", "--llm-endpoint", "https://bedrock-runtime.us-east-1.amazonaws.com/model/test-model/invoke", "--llm-model", "test-model", "--llm-aws-region", "us-east-1", "--llm-aws-access-key-env", "SCOUT_TEST_ACCESS", "--llm-aws-secret-key-env", "SCOUT_TEST_SECRET"}
	for _, session := range []bool{false, true} {
		args := append([]string(nil), common...)
		if session {
			args = append(args, "--llm-aws-session-token-env", "SCOUT_TEST_SESSION")
		}
		args = append(args, "target")
		r, err := parseRequest("scan", args, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		if r.settings.Scanner.Review.Provider.Identity().Model != "test-model" {
			t.Fatal("Bedrock provider lost")
		}
	}
	t.Setenv("SCOUT_TEST_ACCESS", "")
	if _, err := parseRequest("scan", append(common, "target"), &bytes.Buffer{}); err == nil {
		t.Fatal("missing explicit access key accepted")
	}
	t.Setenv("SCOUT_TEST_ACCESS", "TESTACCESS123")
	t.Setenv("SCOUT_TEST_SECRET", "")
	if _, err := parseRequest("scan", append(common, "target"), &bytes.Buffer{}); err == nil {
		t.Fatal("missing explicit secret accepted")
	}
	t.Setenv("SCOUT_TEST_SECRET", "fixture-secret-only")
	t.Setenv("SCOUT_TEST_SESSION", "")
	if _, err := parseRequest("scan", append(append([]string(nil), common...), "--llm-aws-session-token-env", "SCOUT_TEST_SESSION", "target"), &bytes.Buffer{}); err == nil {
		t.Fatal("missing explicit session accepted")
	}
}

func TestConfiguredReviewerTokenOverrideRetainsEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scout.json")
	if err := os.WriteFile(path, []byte(`{"schema":"scout.config/v1","profile":"custom","checks":{"python":false,"yaml":false,"toml":false,"yara":false},"review":{"provider":"chat-completions","endpoint":"https://example.invalid/v1/chat/completions","model":"test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := parseRequest("scan", []string{"--config", path, "--allow-source-upload", "--llm-max-output-tokens", "4096", "target"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if r.settings.Scanner.Review == nil || r.settings.Scanner.Review.Provider.Identity().Model != "test" || r.settings.Reviewer.Provider.MaxOutputTokens != 4096 {
		t.Fatal("single budget override lost the configured reviewer")
	}
}

func TestConfiguredReviewerCanBeDisabledBeforeConsentAndCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scout.json")
	if err := os.WriteFile(path, []byte(`{"schema":"scout.config/v1","profile":"review","review":{"provider":"chat-completions","endpoint":"https://example.invalid/v1/chat/completions","model":"test","key_env":"SCOUT_UNAVAILABLE_TEST_KEY"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCOUT_UNAVAILABLE_TEST_KEY", "")
	r, err := parseRequest("scan", []string{"--config", path, "--semantic=false", "--profile", "basic", "target"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if r.settings.Scanner.Review != nil || r.settings.Reviewer != nil {
		t.Fatal("disabled reviewer activated")
	}
}

func reducedCommandFlags() []string {
	return []string{"--profile", "custom", "--python-ast=false", "--yaml-parser=false", "--toml-parser=false", "--yara=false", "--skillspector-patterns"}
}

type brokenMCPInput struct{}

func (brokenMCPInput) Read([]byte) (int, error) { return 0, errors.New("fixture input failed") }

func (brokenMCPInput) Close() error { return nil }
