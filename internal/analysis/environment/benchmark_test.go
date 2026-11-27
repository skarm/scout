package environment_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/environment"
	"github.com/skarm/scout/report"
)

func BenchmarkSkillDescriptionOverlap(b *testing.B) {
	for _, count := range []int{16, 240} {
		b.Run(fmt.Sprintf("skills-%d", count), func(b *testing.B) {
			topics := []string{
				"audit invoices reconcile supplier balances record overdue payments",
				"translate messages preserve formatting localize customer notifications",
				"review code detect race conditions suggest synchronization changes",
				"inspect charts calculate quarterly revenue explain seasonal trends",
				"annotate transcripts identify speakers extract key discussion points",
				"deploy applications verify infrastructure configs compare production settings",
				"group alerts diagnose network incidents correlate event timestamps",
				"clean datasets normalize columns remove duplicates validate schemas",
			}
			variants := strings.Fields("routine weekly monthly daily upcoming")
			surface := environment.Surface{Complete: true}
			for index := range count {
				desc := topics[index%len(topics)] + " for " + variants[index/len(topics)%len(variants)]
				surface.Facts = append(surface.Facts, environment.SurfaceFact{
					Kind: report.EnvironmentSkillDescription, Value: desc,
					Source: report.SourceRef{Path: fmt.Sprintf("skills/%03d/SKILL.md", index), ByteEnd: len(desc)},
				})
			}
			surfaces := []environment.Surface{surface}
			targets := []report.TargetResult{{ID: "root", State: report.RunComplete}}
			b.ReportAllocs()
			for b.Loop() {
				r := environment.Build(b.Context(), surfaces, targets, 1024, report.MaxEnvironmentOperations)
				if len(r.Observations) == 0 {
					b.Fatal("missing overlaps")
				}
			}
		})
	}
}
