package analyzer_test

import (
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

func TestCloudDirectionRequiresLiteralDownloadAndSafeContext(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         int
	}{
		{"aws copy", "#!/bin/sh\naws s3 cp s3://demo-bucket/report.txt ./report.txt\n", 0},
		{"gcs copy", "gsutil cp gs://demo-bucket/report.txt ./report.txt\n", 0},
		{"aws sync with shell setup", "set -eu\naws s3 sync --quiet s3://demo-bucket/ ./reports\n", 0},
		{"gcs sync", "gsutil rsync -r gs://demo-bucket/reports ./reports\n", 0},
		{"download followed by upload", "aws s3 cp s3://demo-bucket/report.txt ./report.txt\naws s3 cp ./report.txt s3://demo-bucket/archive.txt\n", 1},
		{"upload", "aws s3 cp ./report.txt s3://demo-bucket/archive.txt\n", 1},
		{"deletion flag", "aws s3 sync --delete s3://demo-bucket/archive ./reports\n", 1},
		{"dynamic destination", "aws s3 cp s3://demo-bucket/archive \"$DEST\"\n", 1},
		{"compound", "aws s3 cp s3://demo-bucket/archive - | cat\n", 1},
		{"rebound launcher", "aws() { printf x; }\naws s3 cp s3://demo-bucket/archive ./report.txt\n", 1},
		{"unknown shebang", "#!/usr/bin/env -S bash -x\naws s3 cp s3://demo-bucket/archive ./report.txt\n", 1},
		{"relative after cd", "cd /tmp\naws s3 cp s3://demo-bucket/archive ./report.txt\n", 1},
		{"absolute after cd", "cd /tmp\naws s3 cp s3://demo-bucket/archive /tmp/report.txt\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := prepared(t.Context(), artifact.NewFile("download.sh", []byte(tc.script), false))
			result, err := pluginRule(t, "NV-E5").Find(t.Context(), doc, 8)
			if err != nil || len(result.Matches) != tc.want {
				t.Fatalf("unexpected cloud transfer findings: %+v, %v", result, err)
			}
		})
	}
}

func TestEnvironmentPassthroughOnlyLowersProvenLocalUse(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("native Python frontend required")
	}
	registry, err := parse.WithFrontends(frontend.Options{Python: true, Timeout: frontend.DefaultOptions().Timeout})
	if err != nil {
		t.Fatal(err)
	}
	const imports = "import os\nimport subprocess\n"
	for _, tc := range []struct {
		name, code string
		severity   report.Severity
	}{
		{"inline copy", "subprocess.run(['python', '--version'], env=os.environ.copy())\n", report.Low},
		{"function local copy", "def run():\n    env = dict(os.environ)\n    subprocess.run(['python', '--version'], env=env)\n", report.Low},
		{"entry point copy", "if __name__ == '__main__':\n    env = dict(os.environ)\n    subprocess.run(['python', '--version'], env=env)\n", report.Low},
		{"exported module binding", "child_env = dict(os.environ)\nsubprocess.run(['python', '--version'], env=child_env)\n", report.Medium},
		{"other use", "def run():\n    env = dict(os.environ)\n    print(env)\n    subprocess.run(['python', '--version'], env=env)\n", report.Medium},
		{"rebound launcher", "subprocess = wrapper\nsubprocess.run(['python', '--version'], env=dict(os.environ))\n", report.Medium},
		{"function shadowed", "def run(subprocess):\n    subprocess.run(['python', '--version'], env=dict(os.environ))\n", report.Medium},
		{"later local shadowing", "def run():\n    subprocess.run(['python', '--version'], env=dict(os.environ))\n    subprocess = other\n", report.Medium},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := artifact.NewFile("process.py", []byte(imports+tc.code), false)
			doc := document.PrepareAllWithRegistry(t.Context(), []artifact.File{file}, registry)[0]
			rule := pluginRule(t, "NV-E2")
			result, err := rule.Find(t.Context(), doc, 8)
			if err != nil || len(result.Matches) == 0 {
				t.Fatalf("environment evidence missing: %+v, %v", result, err)
			}
			for _, match := range result.Matches {
				got := match.Severity
				if got == "" {
					got = rule.Rule().Severity
				}
				if got != tc.severity {
					t.Fatalf("severity %q, want %q: %+v", got, tc.severity, result)
				}
			}
		})
	}
}
