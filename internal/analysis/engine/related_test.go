package engine //nolint:testpackage // Exercises private coverage reduction and related-evidence admission.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestRelatedEvidenceRejectsInvalidReferencesWithoutChangingIdentity(t *testing.T) {
	file := artifact.NewFile("note.txt", []byte("aéz"), false)
	doc := document.Prepare(context.Background(), file)
	docs := map[string]document.File{"note.txt": doc}
	valid := report.SourceRef{
		Path:       "note.txt",
		SHA256:     file.Metadata().SHA256,
		ByteStart:  1,
		ByteEnd:    3,
		SpanSHA256: artifact.Hash([]byte("é")),
	}
	for _, tc := range []struct {
		name, want string
		change     func(*report.SourceRef)
	}{
		{name: "unknown", want: "unknown related object", change: func(r *report.SourceRef) { r.Path = "missing.txt" }},
		{
			name:   "object-digest",
			want:   "related object digest",
			change: func(r *report.SourceRef) { r.SHA256 = "different" },
		},
		{name: "negative", want: "invalid span", change: func(r *report.SourceRef) { r.ByteStart = -1 }},
		{name: "outside", want: "invalid span", change: func(r *report.SourceRef) { r.ByteEnd = 99 }},
		{name: "empty", want: "invalid span", change: func(r *report.SourceRef) { r.ByteEnd = r.ByteStart }},
		{name: "utf8", want: "span bisects UTF-8", change: func(r *report.SourceRef) { r.ByteStart = 2 }},
		{
			name:   "span-digest",
			want:   "related evidence digest",
			change: func(r *report.SourceRef) { r.SpanSHA256 = "different" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := valid
			tc.change(&bad)
			finding := report.Finding{ID: "seed"}
			err := attachRelated(&finding, []report.SourceRef{valid, bad}, docs)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if finding.ID != "seed" || !reflect.DeepEqual(finding.RelatedEvidence, []report.SourceRef{valid}) {
				t.Fatalf("failure changed identity or lost the accepted prefix: %+v", finding)
			}
		})
	}
}

func TestRelatedEvidenceIdentityOrderAndReferenceLimit(t *testing.T) {
	file := artifact.NewFile("note.txt", []byte("ab"), false)
	docs := map[string]document.File{"note.txt": document.Prepare(context.Background(), file)}
	a := report.SourceRef{
		Path:       "note.txt",
		SHA256:     file.Metadata().SHA256,
		ByteStart:  0,
		ByteEnd:    1,
		SpanSHA256: artifact.Hash([]byte("a")),
	}
	b := a
	b.ByteStart, b.ByteEnd, b.SpanSHA256 = 1, 2, artifact.Hash([]byte("b"))
	finding := report.Finding{ID: "seed", RelatedEvidence: []report.SourceRef{b}}
	if err := attachRelated(&finding, nil, docs); err != nil || finding.ID != "seed" || !reflect.DeepEqual(finding.RelatedEvidence, []report.SourceRef{b}) {
		t.Fatal("empty references changed the finding")
	}
	if err := attachRelated(&finding, []report.SourceRef{a}, docs); err != nil {
		t.Fatal(err)
	}
	want := artifact.Hash([]byte(strings.Join([]string{"seed", "note.txt", a.SHA256, "0", "1", a.SpanSHA256}, "\x00")))
	if finding.ID != want || !reflect.DeepEqual(finding.RelatedEvidence, []report.SourceRef{b, a}) {
		t.Fatalf("wire identity or append order changed: %+v", finding)
	}
	for _, refs := range [][]report.SourceRef{{a, b}, {b, a}} {
		item := report.Finding{ID: "seed"}
		if err := attachRelated(&item, refs, docs); err != nil {
			t.Fatal(err)
		}
		if finding.ID == item.ID {
			t.Fatal("different reference sequences have the same identity")
		}
		finding = item
	}
	refs := make([]report.SourceRef, 8, 9)
	for i := range refs {
		refs[i] = a
	}
	item := report.Finding{ID: "seed"}
	if err := attachRelated(&item, refs, docs); err != nil || len(item.RelatedEvidence) != 8 {
		t.Fatalf("exact reference limit rejected: %v", err)
	}
	item = report.Finding{ID: "seed"}
	err := attachRelated(&item, append(refs, a), docs)
	if err == nil || err.Error() != "related evidence budget" || item.ID != "seed" || len(item.RelatedEvidence) != 0 {
		t.Fatalf("over-limit references partly accepted: %+v, %v", item, err)
	}
}
