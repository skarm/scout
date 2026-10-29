package document_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestShellCandidateKeepsIndependentAcceptedViews(t *testing.T) {
	calls := 0
	text := "curl x\nsh x\n"
	d := candidateDocument(t, candidateBackend{calls: &calls, bytes: 1024}, text)
	d = d.WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: 7}}, false)
	units, limited := d.ShellCandidates()
	if limited || calls != 2 || len(units) != 1 {
		t.Fatalf("candidate retries lost acceptance: calls=%d units=%+v limited=%v", calls, units, limited)
	}
	tree := units[0].Tree.(parse.ShellTree)
	if units[0].View.Text() != text || tree.DeclarationView == nil || tree.DeclarationView.Text() != "curl x\n" {
		t.Fatalf("grammar projections used wrong extent: execution=%q declaration=%v", units[0].View.Text(), tree.DeclarationView)
	}
	at, err := tree.DeclarationView.Original(source.Span{Start: 0, End: 6})
	if err != nil || text[at.Start:at.End] != "curl x" {
		t.Fatal("candidate evidence mapping changed", at, err)
	}
}

func TestShellCandidateRetrySpendsOriginalBackendQuota(t *testing.T) {
	calls := 0
	text := "curl x\nsh x\nthird line\n"
	d := candidateDocument(t, candidateBackend{calls: &calls, bytes: 24, failExecution: true}, text)
	d = d.WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: 7}}, false)
	units, limited := d.ShellCandidates()
	if !limited || calls != 2 || len(units) != 1 {
		t.Fatalf("parser retry reset aggregate bytes: calls=%d limited=%v units=%+v", calls, limited, units)
	}
	if len(d.Diagnostics()) != 0 || len(d.Units()) != 0 || d.HasParsedUnits() {
		t.Fatalf("auxiliary parser boundary became an ordinary source obligation: diagnostics=%+v units=%+v", d.Diagnostics(), d.Units())
	}
}

func TestShellCandidatePreparationCannotReopenFrozenDocuments(t *testing.T) {
	calls := 0
	d := candidateDocument(t, candidateBackend{calls: &calls, bytes: 1024}, "curl x\n")
	frozen := document.Freeze([]document.File{d})[0]
	frozen = frozen.WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: 7}}, false)
	units, limited := frozen.ShellCandidates()
	if calls != 0 || len(units) != 0 || !limited {
		t.Fatalf("frozen document reopened parser: calls=%d units=%+v limited=%v", calls, units, limited)
	}
}

func TestShellCandidateAdmitsExactParserByteBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name              string
		bytes, end, calls int
	}{{name: "unit", bytes: 12, end: 12, calls: 1}, {name: "aggregate-retry", bytes: 19, end: 7, calls: 2}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			text := "curl x\nsh x\n"
			doc := candidateDocument(t, candidateBackend{calls: &calls, bytes: tc.bytes}, text)
			doc = doc.WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: tc.end}}, false)
			units, limited := doc.ShellCandidates()
			if limited || calls != tc.calls || len(units) != 1 || units[0].Status != "parsed_limited" {
				t.Fatalf("exact admitted byte quota rejected: calls=%d units=%+v limited=%v diagnostics=%+v", calls, units, limited, doc.Diagnostics())
			}
		})
	}
}

func TestShellCandidateGrammarRejectionDoesNotPublishPartialTrees(t *testing.T) {
	calls := 0
	doc := candidateDocument(t, candidateBackend{
		calls:              &calls,
		bytes:              1024,
		failExecution:      true,
		declarationFailure: "unsupported_syntax",
	}, "curl prose\n")
	doc = doc.WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: 11}}, false)
	units, limited := doc.ShellCandidates()
	if limited || calls != 1 || len(units) != 1 || len(doc.Diagnostics()) != 0 || len(doc.Units()) != 0 || doc.HasParsedUnits() {
		t.Fatalf("rejected prose became structured source: calls=%d limited=%v candidates=%+v diagnostics=%+v", calls, limited, units, doc.Diagnostics())
	}
	tree := units[0].Tree.(parse.ShellTree)
	if tree.Tree != nil || tree.Declarations != nil {
		t.Fatalf("unaccepted partial shell trees published as candidate facts: %+v", tree)
	}
}

func TestShellCandidateDeclarationLimitRetainsExecutionButReportsGap(t *testing.T) {
	calls := 0
	text := "curl x\nsh x\n"
	doc := candidateDocument(t, candidateBackend{calls: &calls, bytes: 1024, declarationFailure: "parser_limit"}, text)
	doc = doc.WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: len(text)}}, false)
	units, limited := doc.ShellCandidates()
	if !limited || calls != 1 || len(units) != 1 || len(doc.Diagnostics()) != 0 {
		t.Fatalf("declaration parser budget lost: calls=%d limited=%v candidates=%+v diagnostics=%+v", calls, limited, units, doc.Diagnostics())
	}
	tree := units[0].Tree.(parse.ShellTree)
	if tree.Tree == nil || tree.Declarations != nil {
		t.Fatalf("candidate grammar acceptance was conflated: %+v", tree)
	}
}

func TestShellCandidatesSpendOrdinarySourceAggregateQuota(t *testing.T) {
	calls := 0
	registry, err := parse.New(candidateBackend{calls: &calls, bytes: 22})
	if err != nil {
		t.Fatal(err)
	}
	text := "curl x\nsh x\n"
	docs := document.PrepareAllWithRegistry(context.Background(), []artifact.File{
		artifact.NewFile("prior.sh", []byte("echo first\n"), false),
		artifact.NewFile("input.txt", []byte(text), false),
	}, registry)
	doc := docs[1].WithShellCandidates(context.Background(), []source.Span{{Start: 0, End: len(text)}}, false)
	units, limited := doc.ShellCandidates()
	if !limited || calls != 1 || len(units) != 1 || units[0].Status != "budget_exceeded" || len(doc.Diagnostics()) != 0 {
		t.Fatalf("auxiliary parsing reset ordinary source quota: calls=%d limited=%v candidates=%+v diagnostics=%+v", calls, limited, units, doc.Diagnostics())
	}
}

type candidateBackend struct {
	calls              *int
	failExecution      bool
	bytes              int
	declarationFailure string
}

func (b candidateBackend) Descriptor() parse.Descriptor {
	return parse.Descriptor{
		ID:        "candidate-fixture",
		Language:  "shell",
		Version:   "1",
		UnitBytes: b.bytes,
		ScanBytes: b.bytes,
	}
}

func (b candidateBackend) Parse(_ context.Context, v source.View) (any, error) {
	*b.calls++
	var executionErr error
	if b.failExecution || strings.Count(v.Text(), "\n") < 2 {
		executionErr = &parse.Failure{Category: "unsupported_syntax"}
	}
	var declarationErr error
	if b.declarationFailure != "" {
		declarationErr = &parse.Failure{Category: b.declarationFailure}
	}
	return parse.ShellTree{
		Tree:             &shellsyntax.File{},
		Declarations:     &shellsyntax.File{},
		ExecutionError:   executionErr,
		DeclarationError: declarationErr,
	}, executionErr
}

func candidateDocument(t *testing.T, backend candidateBackend, text string) document.File {
	t.Helper()
	registry, err := parse.New(backend)
	if err != nil {
		t.Fatal(err)
	}
	return document.PrepareAllWithRegistry(context.Background(), []artifact.File{artifact.NewFile("input.md", []byte(text), false)}, registry)[0]
}
