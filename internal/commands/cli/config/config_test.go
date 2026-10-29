package config_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/internal/commands/cli/config"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestDefaultsAndPartialMerge(t *testing.T) {
	got, err := parseResolved([]byte(`{"schema":"scout.config/v1"}`), config.Grants{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Scanner, scout.DefaultOptions()) || got.Policy.FailAt != report.High {
		t.Fatalf("defaults changed: %#v", got)
	}
	got, err = parseResolved([]byte(`{"schema":"scout.config/v1","profile":"custom","checks":{"python":false},"concurrency":{"workers":7},"timeout":"45s","harness":"codex","policy":{"fail_at":"critical","baseline":"approvals.json","allow_globs":true,"review_below_threshold":true},"signatures":{"rules_file":"extra.yar","timeout":"2s"}}`), config.Grants{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scanner.Concurrency != (scout.Concurrency{Targets: 1, Workers: 7}) || got.Scanner.Limits.Timeout != 45*time.Second || got.Scanner.Harness.Host != "codex" {
		t.Fatalf("partial defaults lost: %#v", got.Scanner)
	}
	if got.Scanner.Checks == nil || *got.Scanner.Checks != (scout.Checks{
		Patterns: true,
		YAML:     true,
		TOML:     true,
		YARA:     true,
	}) {
		t.Fatalf("checks patch not merged: %#v", got.Scanner.Checks)
	}
	if got.Policy.FailAt != report.Critical || !got.Policy.AllowGlobs || !got.Policy.ReviewBelowThreshold || got.BaselinePath != "approvals.json" || got.ExtraRulesPath != "extra.yar" || got.Scanner.Signatures.Timeout != 2*time.Second {
		t.Fatalf("policy/signature settings lost: %#v", got)
	}
}

func TestStrictConfigurationBoundary(t *testing.T) {
	for name, input := range map[string]string{
		"missing schema":    `{}`,
		"wrong schema":      `{"schema":"scout.config/v2"}`,
		"unknown":           `{"schema":"scout.config/v1","secret":"never"}`,
		"unknown nested":    `{"schema":"scout.config/v1","limits":{"capture":{"max_file_byte":1}}}`,
		"case alias":        `{"Schema":"scout.config/v1"}`,
		"nested case alias": `{"schema":"scout.config/v1","policy":{"Fail_At":"high"}}`,
		"duplicate":         `{"schema":"scout.config/v1","schema":"scout.config/v1"}`,
		"nested duplicate":  `{"schema":"scout.config/v1","concurrency":{"workers":2,"workers":3}}`,
		"escaped duplicate": `{"schema":"scout.config/v1","policy":{"fail_at":"high","fail_\u0061t":"low"}}`,
		"trailing":          `{"schema":"scout.config/v1"} {}`,
		"null":              `{"schema":"scout.config/v1","policy":null}`,
		"wrong type":        `{"schema":"scout.config/v1","concurrency":{"workers":"2"}}`,
		"fractional budget": `{"schema":"scout.config/v1","limits":{"max_service_requests":1.5}}`,
		"negative unsigned": `{"schema":"scout.config/v1","limits":{"analysis":{"max_operations":-1}}}`,
		"oversized":         strings.Repeat(" ", jsonconfig.MaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseResolved([]byte(input), config.Grants{}, nil); err == nil || !reflect.DeepEqual(got, config.Settings{}) {
				t.Fatalf("invalid config accepted or returned partial settings: %#v %v", got, err)
			}
		})
	}
}

func TestEveryBudgetPatchPreservesExplicitZero(t *testing.T) {
	input := `{"schema":"scout.config/v1","concurrency":{"targets":0,"workers":0},"limits":{"capture":{"max_entries":0,"max_files":0,"max_file_bytes":0,"max_total_bytes":0,"max_archive_bytes":0,"max_path_bytes":0,"max_depth":0},"extraction":{"max_depth":0,"max_objects":0,"max_entries":0,"max_object_bytes":0,"max_total_bytes":0},"analysis":{"max_operations":0,"max_matches_per_rule":0,"parser_timeout":"1s"},"retention":{"max_findings":0},"max_capture_bytes":0,"max_extracted_bytes":0,"max_capture_files":0,"max_capture_entries":0,"max_service_requests":0}}`
	got, err := parseResolved([]byte(input), config.Grants{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := scout.Limits{Analysis: scout.AnalysisLimits{ParserTimeout: time.Second}, Timeout: 2 * time.Minute}
	if got.Scanner.Limits != want || got.Scanner.Concurrency != (scout.Concurrency{}) {
		t.Fatalf("explicit zero replaced with default: %#v", got.Scanner)
	}
}

func TestServiceGrantsAndOfflineCache(t *testing.T) {
	if _, err := parseResolved([]byte(`{"schema":"scout.config/v1","download":{"timeout":"10s"}}`), config.Grants{}, nil); err == nil {
		t.Fatal("download config granted its own network access")
	}
	got, err := parseResolved([]byte(`{"schema":"scout.config/v1","download":{"timeout":"10s","allow_loopback":true},"vulnerabilities":{"cache":"missing-file.json","endpoint":"https://api.osv.dev/v1/querybatch","max_requests":5}}`), config.Grants{Download: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scanner.Download == nil || !got.Scanner.Download.Enabled || !got.Scanner.Download.AllowLoopback || got.Scanner.Download.Timeout != 10*time.Second || got.OSVCachePath != "missing-file.json" || got.Scanner.Vulnerabilities == nil || got.Scanner.Vulnerabilities.AllowNetwork || len(got.Scanner.Vulnerabilities.Offline) != 0 || got.Scanner.Vulnerabilities.MaxRequests != 5 {
		t.Fatalf("grants/cache not preserved: %#v", got)
	}
	got, err = parseResolved([]byte(`{"schema":"scout.config/v1","vulnerabilities":{}}`), config.Grants{
		VulnerabilityNetwork: true,
		Download:             true,
	}, nil)
	if err != nil || got.Scanner.Vulnerabilities == nil || !got.Scanner.Vulnerabilities.AllowNetwork || got.Scanner.Download == nil {
		t.Fatalf("explicit grants not honored: %#v %v", got, err)
	}
	if _, err := parseResolved([]byte(`{"schema":"scout.config/v1","vulnerabilities":{}}`), config.Grants{}, nil); err == nil {
		t.Fatal("uncached vulnerability queries accepted without grant")
	}
}

func TestReviewConsentPrecedesCredentialLookup(t *testing.T) {
	input := []byte(`{"schema":"scout.config/v1","profile":"review","review":{"provider":"chat-completions","endpoint":"https://example.com/v1/chat/completions","model":"model-v1","key_env":"SCOUT_REVIEW_KEY","quality":true,"max_requests":3,"max_input_bytes":65536,"timeout":"8s"}}`)
	calls := 0
	lookup := func(name string) (string, bool) {
		calls++
		if name != "SCOUT_REVIEW_KEY" {
			t.Fatalf("wrong credential environment name %q", name)
		}
		return "test-key", true
	}
	if _, err := parseResolved(input, config.Grants{}, lookup); err == nil || calls != 0 {
		t.Fatalf("review touched environment before consent: calls=%d err=%v", calls, err)
	}
	got, err := parseResolved(input, config.Grants{SourceUpload: true}, lookup)
	if err != nil || calls != 1 {
		t.Fatalf("review configuration: calls=%d err=%v", calls, err)
	}
	if _, ok := got.Scanner.Review.Provider.(*review.HTTPProvider); !ok {
		t.Fatalf("wrong provider: %T", got.Scanner.Review.Provider)
	}
	ro := got.Scanner.Review.Settings
	if !ro.Enabled || !ro.AllowSourceUpload || !ro.QualityPolicy || ro.Timeout != 8*time.Second || ro.MaxRequests != 3 || ro.MaxInputBytes != 65536 || ro.MaxResponseBytes != 64<<10 {
		t.Fatalf("review patch/defaults lost: %#v", ro)
	}
}

func TestReviewProviderValidation(t *testing.T) {
	for _, provider := range []string{"anthropic", "anthropic-proxy"} {
		got, err := parseResolved([]byte(`{"schema":"scout.config/v1","review":{"provider":"`+provider+`","endpoint":"https://example.com/v1/messages","model":"model-v1"}}`), config.Grants{SourceUpload: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.Scanner.Review.Provider.(*review.MessagesProvider); !ok {
			t.Fatalf("wrong messages provider: %T", got.Scanner.Review.Provider)
		}
	}
	for name, patch := range map[string]string{
		"missing provider":            `"endpoint":"https://example.com","model":"m"`,
		"unknown provider":            `"provider":"shell","endpoint":"https://example.com","model":"m"`,
		"bedrock missing credentials": `"provider":"bedrock","endpoint":"https://example.com","model":"m"`,
		"malformed endpoint":          `"provider":"chat-completions","endpoint":"http://example.com","model":"m"`,
		"missing model":               `"provider":"chat-completions","endpoint":"https://example.com"`,
		"unset key":                   `"provider":"chat-completions","endpoint":"https://example.com","model":"m","key_env":"ABSENT"`,
		"literal key":                 `"provider":"chat-completions","endpoint":"https://example.com","model":"m","api_key":"secret"`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseResolved([]byte(`{"schema":"scout.config/v1","review":{`+patch+`}}`), config.Grants{SourceUpload: true}, func(string) (string, bool) { return "", false })
			if err == nil {
				t.Fatal("malformed provider accepted")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error contains raw credentials")
			}
		})
	}
}

func TestReviewLoopbackAndCredentialBoundary(t *testing.T) {
	base := `{"schema":"scout.config/v1","review":{"provider":"chat-completions","endpoint":"http://127.0.0.1:1/v1/chat/completions","model":"model-v1"`
	if _, err := parseResolved([]byte(base+`}}`), config.Grants{SourceUpload: true}, nil); err == nil {
		t.Fatal("loopback permission inferred from source-upload consent")
	}
	if _, err := parseResolved([]byte(base+`,"allow_loopback":true}}`), config.Grants{SourceUpload: true}, nil); err != nil {
		t.Fatalf("explicit loopback provider config rejected: %v", err)
	}
	calls := 0
	lookup := func(string) (string, bool) { calls++; return "raw-key\nmalicious", true }
	if _, err := parseResolved([]byte(base+`,"allow_loopback":true,"key_env":"BAD-NAME"}}`), config.Grants{SourceUpload: true}, lookup); err == nil || calls != 0 {
		t.Fatalf("invalid key name reached environment: calls=%d err=%v", calls, err)
	}
	if _, err := parseResolved([]byte(base+`,"allow_loopback":true,"key_env":"KEY"}}`), config.Grants{SourceUpload: true}, lookup); err == nil || strings.Contains(err.Error(), "raw-key") {
		t.Fatalf("invalid credential accepted or echoed: %v", err)
	}
}

func TestBedrockConsentAndExplicitCredentials(t *testing.T) {
	const input = `{"schema":"scout.config/v1","profile":"review","review":{"provider":"bedrock","endpoint":"https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.test-v1:0/invoke","model":"anthropic.test-v1:0","aws_region":"us-east-1","access_key_env":"SCOUT_BEDROCK_ACCESS","secret_key_env":"SCOUT_BEDROCK_SECRET","session_token_env":"SCOUT_BEDROCK_SESSION","timeout":"8s"}}`
	values := map[string]string{
		"SCOUT_BEDROCK_ACCESS":  "ACCESSKEY12345",
		"SCOUT_BEDROCK_SECRET":  "scout-secret-test-value",
		"SCOUT_BEDROCK_SESSION": "session-test-value",
	}
	var calls []string
	lookup := func(name string) (string, bool) {
		calls = append(calls, name)
		value, ok := values[name]
		return value, ok
	}
	if got, err := parseResolved([]byte(input), config.Grants{}, lookup); err == nil || !strings.Contains(err.Error(), "source-upload grant") || len(calls) != 0 || !reflect.DeepEqual(got, config.Settings{}) {
		t.Fatalf("consent boundary: lookups=%v err=%v", calls, err)
	}
	got, err := parseResolved([]byte(input), config.Grants{SourceUpload: true}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"SCOUT_BEDROCK_ACCESS", "SCOUT_BEDROCK_SECRET", "SCOUT_BEDROCK_SESSION"}) {
		t.Fatalf("unexpected credential lookups: %v", calls)
	}
	provider, ok := got.Scanner.Review.Provider.(*review.MessagesProvider)
	if !ok {
		t.Fatalf("wrong Bedrock provider: %T", got.Scanner.Review.Provider)
	}
	expected, err := review.NewMessages(review.MessagesOptions{
		HTTPOptions: review.HTTPOptions{
			Endpoint:         "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.test-v1:0/invoke",
			Model:            "anthropic.test-v1:0",
			Timeout:          8 * time.Second,
			MaxOutputTokens:  2048,
			MaxResponseBytes: 64 << 10,
		},
		Transport:       "bedrock",
		Region:          "us-east-1",
		AccessKeyID:     values["SCOUT_BEDROCK_ACCESS"],
		SecretAccessKey: values["SCOUT_BEDROCK_SECRET"],
		SessionToken:    values["SCOUT_BEDROCK_SESSION"],
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := provider.Identity()
	if identity != expected.Identity() || identity.Provider != "bedrock-messages-json" || identity.EndpointSHA256 == "" || identity.SettingsSHA256 == "" {
		t.Fatalf("Bedrock transport identity lost: %+v", identity)
	}
	if !got.Scanner.Review.Settings.Enabled || !got.Scanner.Review.Settings.AllowSourceUpload || got.Scanner.Review.Settings.Timeout != 8*time.Second {
		t.Fatal("review grant or limits lost")
	}
	values["SCOUT_BEDROCK_ACCESS"] = "ROTATEDKEY12345"
	values["SCOUT_BEDROCK_SECRET"] = "rotated-secret-test-value"
	values["SCOUT_BEDROCK_SESSION"] = "rotated-session-test-value"
	rotated, err := parseResolved([]byte(input), config.Grants{SourceUpload: true}, lookup)
	if err != nil || rotated.Scanner.Review.Provider.Identity() != identity {
		t.Fatalf("identity includes credential material: %v", err)
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range values {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("identity exposes credentials")
		}
	}
}

func TestBedrockCredentialFailuresNeverUseAmbientCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENTKEY12345")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret-test-value")
	t.Setenv("AWS_SESSION_TOKEN", "ambient-session-test-value")
	const base = `{"schema":"scout.config/v1","review":{"provider":"bedrock","endpoint":"https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.test-v1:0/invoke","model":"anthropic.test-v1:0"`
	for _, tc := range []struct {
		name, patch string
		missing     bool
		lookups     []string
	}{
		{
			name:    "missing region",
			patch:   `,"access_key_env":"ACCESS","secret_key_env":"SECRET"`,
			missing: false,
			lookups: nil,
		},
		{
			name:    "missing access name",
			patch:   `,"aws_region":"us-east-1","secret_key_env":"SECRET"`,
			missing: false,
			lookups: nil,
		},
		{
			name:    "missing secret name",
			patch:   `,"aws_region":"us-east-1","access_key_env":"ACCESS"`,
			missing: false,
			lookups: nil,
		},
		{
			name:    "empty access name",
			patch:   `,"aws_region":"us-east-1","access_key_env":"","secret_key_env":"SECRET"`,
			missing: false,
			lookups: nil,
		},
		{
			name:    "invalid secret name",
			patch:   `,"aws_region":"us-east-1","access_key_env":"ACCESS","secret_key_env":"BAD-NAME"`,
			missing: false,
			lookups: nil,
		},
		{
			name:    "unavailable values",
			patch:   `,"aws_region":"us-east-1","access_key_env":"ACCESS","secret_key_env":"SECRET"`,
			missing: true,
			lookups: []string{"ACCESS"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			lookup := func(name string) (string, bool) {
				calls = append(calls, name)
				if tc.missing {
					return "", false
				}
				if name != "ACCESS" {
					t.Fatalf("invalid environment name looked up: %q", name)
				}
				return "ACCESSKEY12345", true
			}
			if got, err := parseResolved([]byte(base+tc.patch+`}}`), config.Grants{SourceUpload: true}, lookup); err == nil || !reflect.DeepEqual(got, config.Settings{}) {
				t.Fatalf("invalid explicit credentials accepted: %v", err)
			}
			if !slices.Equal(calls, tc.lookups) {
				t.Fatalf("credential boundary changed: got %v want %v", calls, tc.lookups)
			}
		})
	}
	const complete = `,"aws_region":"us-east-1","access_key_env":"ACCESS","secret_key_env":"SECRET"`
	if _, err := parseResolved([]byte(base+complete+`}}`), config.Grants{SourceUpload: true}, nil); err == nil {
		t.Fatal("ambient AWS environment used without explicit lookup")
	}
	lookup := func(name string) (string, bool) {
		switch name {
		case "ACCESS":
			return "ACCESSKEY12345", true
		case "SECRET":
			return "scout-secret-test-value", true
		default:
			return "", false
		}
	}
	if _, err := parseResolved([]byte(base+complete+`}}`), config.Grants{SourceUpload: true}, lookup); err != nil {
		t.Fatalf("optional session token required: %v", err)
	}
	if _, err := parseResolved([]byte(base+complete+`,"session_token_env":"MISSING"}}`), config.Grants{SourceUpload: true}, lookup); err == nil {
		t.Fatal("explicit missing session token ignored")
	}
}

func TestReviewRejectsUnexpectedAWSFieldsBeforeLookup(t *testing.T) {
	for _, provider := range []string{"chat-completions", "anthropic", "anthropic-proxy"} {
		for _, field := range []string{"aws_region", "access_key_env", "secret_key_env", "session_token_env"} {
			t.Run(provider+"/"+field, func(t *testing.T) {
				input := `{"schema":"scout.config/v1","review":{"provider":"` + provider + `","endpoint":"https://example.com/v1/messages","model":"model-v1","` + field + `":""}}`
				calls := 0
				lookup := func(string) (string, bool) { calls++; return "scout-test-key", true }
				if got, err := parseResolved([]byte(input), config.Grants{SourceUpload: true}, lookup); err == nil || calls != 0 || !reflect.DeepEqual(got, config.Settings{}) {
					t.Fatalf("unexpected AWS field accepted: lookups=%d err=%v", calls, err)
				}
			})
		}
	}
	input := `{"schema":"scout.config/v1","review":{"provider":"bedrock","endpoint":"https://bedrock-runtime.us-east-1.amazonaws.com/model/m/invoke","model":"m","aws_region":"us-east-1","access_key_env":"ACCESS","secret_key_env":"SECRET","key_env":"KEY"}}`
	calls := 0
	lookup := func(string) (string, bool) { calls++; return "scout-test-key", true }
	if _, err := parseResolved([]byte(input), config.Grants{SourceUpload: true}, lookup); err == nil || calls != 0 {
		t.Fatalf("Bedrock API key accepted or looked up: calls=%d err=%v", calls, err)
	}
}

func TestInvalidDurationsProfilesAndPolicy(t *testing.T) {
	for _, patch := range []string{
		`"timeout":"tomorrow"`, `"timeout":"0s"`, `"timeout":"11m"`,
		`"limits":{"analysis":{"parser_timeout":"11s"}}`, `"signatures":{"timeout":"11s"}`,
		`"harness":"unknown"`, `"profile":"unknown"`, `"profile":"custom"`,
		`"checks":{"python":false}`, `"policy":{"fail_at":"unknown"}`,
		`"download":{"timeout":"3m"}`, `"review":{"provider":"chat-completions","timeout":"3m"}`,
	} {
		if _, err := parseResolved([]byte(`{"schema":"scout.config/v1",`+patch+`}`), config.Grants{
			Download:     true,
			SourceUpload: true,
		}, nil); err == nil {
			t.Fatalf("bad option accepted: %s", patch)
		}
	}
}

func TestRemotePinsAreExplicitAndValidated(t *testing.T) {
	revision := strings.Repeat("a", 40)
	checksum := strings.Repeat("b", 64)
	got, err := parseResolved([]byte(`{"schema":"scout.config/v1","remote_pins":{"https://github.com/example/repo":{"revision":"`+revision+`","sha256":"`+checksum+`"}}}`), config.Grants{}, nil)
	if err != nil || got.RemotePins["https://github.com/example/repo"] != (scout.RemotePin{
		Revision: revision,
		SHA256:   checksum,
	}) {
		t.Fatalf("remote pin lost: %#v %v", got.RemotePins, err)
	}
	for _, pins := range []string{`{"file:///tmp/input":{"sha256":"` + checksum + `"}}`, `{"https://example.com":{}}`, `{"https://example.com":{"revision":"main"}}`, `{"https://example.com":{"sha256":"short"}}`, `{"https://example.com":{"sha256":"` + checksum + `","unknown":true}}`} {
		if _, err := parseResolved([]byte(`{"schema":"scout.config/v1","remote_pins":`+pins+`}`), config.Grants{}, nil); err == nil {
			t.Fatalf("bad remote pin accepted: %s", pins)
		}
	}
}

func TestParseKeepsReviewerPassiveUntilResolve(t *testing.T) {
	settings, err := config.Parse([]byte(`{"schema":"scout.config/v1","review":{"provider":"chat-completions","endpoint":"https://example.invalid/v1/chat/completions","model":"test","key_env":"EXPLICIT_KEY"}}`), config.Grants{SourceUpload: true})
	if err != nil {
		t.Fatal(err)
	}
	if settings.Scanner.Review != nil || settings.Reviewer == nil || settings.Reviewer.Provider.KeyEnv != "EXPLICIT_KEY" {
		t.Fatal("parsing resolved or lost provider configuration")
	}
	calls := 0
	if err := settings.Resolve(func(name string) (string, bool) { calls++; return "fixture-key", name == "EXPLICIT_KEY" }); err != nil || calls != 1 || settings.Scanner.Review == nil {
		t.Fatalf("resolution calls=%d err=%v", calls, err)
	}
}

func parseResolved(data []byte, grants config.Grants, lookup func(string) (string, bool)) (config.Settings, error) {
	settings, err := config.Parse(data, grants)
	if err == nil {
		err = settings.Resolve(lookup)
	}
	if err != nil {
		return config.Settings{}, err
	}
	return settings, nil
}
