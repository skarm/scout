package nativecontract_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/nativecontract"
)

func TestStrictSelftestPlan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*nativecontract.Report)
		bad    bool
	}{
		{name: "full", change: func(*nativecontract.Report) {}, bad: false},
		{name: "missing", change: func(r *nativecontract.Report) { r.Checks = r.Checks[1:] }, bad: true},
		{name: "duplicate", change: func(r *nativecontract.Report) { r.Checks[1] = r.Checks[0] }, bad: true},
		{name: "unavailable", change: func(r *nativecontract.Report) { r.Checks[0].Status = "unavailable" }, bad: true},
		{name: "skip", change: func(r *nativecontract.Report) { r.Checks[0].Status = "skipped" }, bad: true},
		{name: "backend", change: func(r *nativecontract.Report) { r.Checks[0].Backend = "synthetic" }, bad: true},
		{name: "reason", change: func(r *nativecontract.Report) { r.Checks[0].Reason = "partial" }, bad: true},
		{name: "version", change: func(r *nativecontract.Report) { r.Version = "" }, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good()
			tc.change(&r)
			if (nativecontract.Validate(r) != nil) != tc.bad {
				t.Fatal(r)
			}
		})
	}
	ids := nativecontract.IDs()
	ids[0] = "changed"
	if nativecontract.IDs()[0] == "changed" {
		t.Fatal("shared mutable plan")
	}
}

func good() nativecontract.Report {
	r := nativecontract.Report{Schema: "1", Version: "test", Platform: "linux/amd64", Passed: true}
	for _, id := range nativecontract.IDs() {
		backend, _, _ := strings.Cut(id, "-")
		if backend == "yara" {
			backend = "yara-x"
		}
		r.Checks = append(r.Checks, nativecontract.Check{ID: id, Backend: backend, Status: "passed"})
	}
	return r
}
