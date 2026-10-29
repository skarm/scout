package bundle

import (
	"errors"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
	"github.com/skarm/scout/report"
)

var bundleURLs = regexp.MustCompile(`(?i)https?://[^\s<>"'\x60)\]]+`)

func canonicalHost(raw string) string {
	u, e := url.Parse(strings.TrimRight(raw, ".,;"))
	if e != nil || u.User != nil && u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	return host
}

func (b *bundleAnalysis) shellEndpoints(d document.File) {
	name := d.Artifact().Metadata().Path

	err := shell.ObserveNetwork(b.ctx, d, func(value string, s source.Span) { b.endpoint(name, value, b.reference(name, s.Start, s.End)) }, func(s source.Span) { b.secret(name, b.reference(name, s.Start, s.End)) })
	if err != nil {
		b.gap = errors.Join(b.gap, err)
	}
}

func (b *bundleAnalysis) sqlEndpoints(d document.File) {
	for _, u := range d.Units() {
		t, ok := u.Tree.(sqlsyntax.Tree)
		if !ok {
			continue
		}

		for _, statement := range t.Statements {
			b.sqlStatementEndpoints(d, u, statement)
		}
	}
}

func (b *bundleAnalysis) unitRef(d document.File, u document.Unit, s source.Span) report.SourceRef {
	at, e := u.View.Original(s)
	if e != nil {
		b.err = errors.New("bundle unit mapping failed")
		return report.SourceRef{}
	}

	return b.reference(d.Artifact().Metadata().Path, at.Start, at.End)
}

func (b *bundleAnalysis) installHooks(d document.File) {
	name := d.Artifact().Metadata().Path
	for _, u := range d.Units() {
		t, ok := u.Tree.(parse.JSONTree)
		if !ok || t.Root == nil {
			continue
		}

		if path.Base(name) == "package.json" {
			for _, key := range []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"} {
				n := t.Root.Get("scripts").Get(key)
				if value, ok := n.Text(); ok && strings.TrimSpace(value) != "" {
					b.emit(ruleSC004, b.unitRef(d, u, n.Span), b.hookTargets(name, value)...)
				}
			}
		}

		if path.Base(name) == "pyproject.toml" {
			if n := t.Root.Get("build-system").Get("build-backend"); n != nil {
				b.emit(ruleSC004, b.unitRef(d, u, n.Span))
			}
		}
	}

	if path.Base(name) == "setup.py" && len(d.Artifact().Content()) > 0 {
		b.emit(ruleSC004, b.reference(name, 0, len(d.Artifact().Content())))
	}
}

func (b *bundleAnalysis) hookTargets(file, command string) []report.SourceRef {
	var refs []report.SourceRef

	for word := range strings.FieldsSeq(command) {
		word = strings.Trim(word, "\"'")
		if strings.HasPrefix(word, "-") {
			continue
		}

		for _, ext := range []string{".js", ".ts", ".py", ".sh"} {
			if strings.HasSuffix(word, ext) {
				if target := b.resolveLocal(file, word); target != nil {
					refs = append(refs, b.reference(target.Artifact().Metadata().Path, 0, len(target.Artifact().Content())))
				}
			}
		}
	}

	return refs
}

func (b *bundleAnalysis) resolveLocal(file, relative string) *document.File {
	addr, ok := b.addresses[file]
	if !ok || path.IsAbs(relative) || strings.Contains(relative, "\\") {
		return nil
	}

	want := path.Clean(path.Join(path.Dir(addr.Name), relative))
	if want == ".." || strings.HasPrefix(want, "../") {
		return nil
	}

	for name, a := range b.addresses {
		if a.Namespace == addr.Namespace && a.Name == want {
			d := b.docs[name]
			return &d
		}
	}

	return nil
}

func (b *bundleAnalysis) toolCollisions(d document.File) {
	for _, u := range d.Units() {
		t, ok := u.Tree.(parse.JSONTree)
		if !ok || t.Root == nil {
			continue
		}

		seen := map[string]report.SourceRef{}

		var walk func(*jsonconfig.Node, int)

		walk = func(n *jsonconfig.Node, depth int) {
			if n == nil || !b.step() {
				return
			}

			if depth > 32 {
				b.err = errors.New("tool namespace depth limit")
				return
			}

			b.observeTools(d, u, n.Get("tools"), seen)

			for _, m := range n.Members {
				walk(m.Value, depth+1)
			}

			for _, e := range n.Elements {
				walk(e, depth+1)
			}
		}
		walk(t.Root, 0)
	}
}

func (b *bundleAnalysis) sqlStatementEndpoints(d document.File, u document.Unit, statement sqlsyntax.Statement) {
	tokens := statement.Tokens
	for i, tok := range tokens {
		if !b.step() {
			return
		}

		if tok.Kind != "word" && tok.Kind != "identifier" {
			continue
		}

		switch strings.ToUpper(tok.Text) {
		case "HTTP_GET", "HTTP_POST", "HTTP_PUT", "HTTP_DELETE", "HTTP_REQUEST":
		default:
			continue
		}

		if i+2 >= len(tokens) || tokens[i+1].Text != "(" {
			continue
		}

		operand := i + 2
		if tokens[operand].Kind == "word" && (tokens[operand].Text == "URL" || tokens[operand].Text == "URI") {
			operand++
			for operand < len(tokens) && (tokens[operand].Text == ":" || tokens[operand].Text == "=") {
				operand++
			}
		}

		value := ""
		if operand < len(tokens) && tokens[operand].Kind == jsonconfig.KindString {
			value = tokens[operand].Text
		}

		end := tokens[i+1].End
		if operand < len(tokens) {
			end = tokens[operand].End
		}

		ref := b.unitRef(d, u, source.Span{Start: tok.Start, End: end})
		b.endpoint(d.Artifact().Metadata().Path, value, ref)
	}
}

func (b *bundleAnalysis) observeTools(d document.File, u document.Unit, tools *jsonconfig.Node, seen map[string]report.SourceRef) {
	if tools != nil && tools.Kind == jsonconfig.KindArray {
		for _, tool := range tools.Elements {
			name := tool.Get("name")

			key, ok := name.Text()
			if !ok || key == "" {
				continue
			}

			ref := b.unitRef(d, u, name.Span)
			if prior, exists := seen[key]; exists {
				b.emit(ruleTC001, ref, prior)
			} else {
				seen[key] = ref
			}
		}
	}
}
