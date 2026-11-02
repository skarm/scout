package shell

import (
	"context"
	"errors"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

// ObserveNetwork uses the same native command/option grammar as SH001/SH002/SH004.
// Sensitive reads include parameter expansion and supported cat, input redirect
// and curl file-body operations, independently of their eventual use in a sink.
// Callbacks contain captured text for trusted analysis only, never public logs.
func ObserveNetwork(ctx context.Context, doc document.File, network func(string, source.Span), secret func(source.Span), dns func(DNSQuery)) error {
	w := shellWalk{ctx: ctx, outputs: map[string]*check.Facts{}}
	w.observeNetwork = func(value string, s source.Span) {
		at, e := w.view.Original(s)
		if e != nil {
			w.err = e
			return
		}

		network(value, at)
	}

	w.observeSecret = func(s source.Span) {
		at, e := w.view.Original(s)
		if e != nil {
			w.err = e
			return
		}

		secret(at)
	}

	if dns != nil {
		w.observeDNS = func(name string, span source.Span, origin *shellOrigin) {
			at, err := w.view.Original(span)
			if err != nil {
				w.err = err
				return
			}

			query := DNSQuery{Name: name, Span: at}

			if origin != nil {
				for _, s := range append([]source.Span{origin.source}, origin.via...) {
					at, err := w.view.Original(s)
					if err != nil {
						w.err = err
						return
					}

					query.Trace = append(query.Trace, at)
				}
			}

			dns(query)
		}
	}

	w.units(doc.Units())

	return errors.Join(w.err, w.gap, ctx.Err())
}

// DNSQuery retains only the queried operand and its sensitive-data provenance.
// Server, record-type and option operands are not treated as query names.
type DNSQuery struct {
	Name  string
	Span  source.Span
	Trace []source.Span
}

func (a *shellWalk) sensitiveFileRead(span source.Span) *shellOrigin {
	a.emit(ruleSH004, span, nil)

	if a.observeSecret != nil {
		a.observeSecret(span)
	}

	return &shellOrigin{source: span}
}

func (a *shellWalk) observeWget(c *shellsyntax.Command, args []shellValue) {
	if a.observeNetwork == nil {
		return
	}

	r := wgetRequest{}
	for i := 0; i < len(args); i++ {
		next, valid := r.argument(args, i)
		if !valid {
			a.observeNetwork("", c.Span)
			return
		}

		if wgetOption(args[i]) == wgetOperand && httpURL(args[i].text) {
			a.observeNetwork(args[i].text, c.Span)
		}

		i = next
	}
}
