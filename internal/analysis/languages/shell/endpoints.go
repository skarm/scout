package shell

import (
	"context"
	"errors"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

// Observers receive captured syntax for trusted analysis only, never public logs.
type Observers struct {
	Network    func(string, source.Span)
	Secret     func(source.Span)
	DNS        func(DNSQuery)
	Capability func(string, source.Span)
}

// Observe uses the same native command/option grammar as SH001/SH002/SH004.
// Sensitive reads include parameter expansion and supported cat, input redirect
// and curl file-body operations, independently of their eventual use in a sink.
// Callbacks contain captured text for trusted analysis only, never public logs.
func Observe(ctx context.Context, doc document.File, observers Observers) error {
	w := shellWalk{ctx: ctx, outputs: map[string]*check.Facts{}}
	if observers.Network != nil {
		w.observeNetwork = func(value string, s source.Span) {
			at, e := w.view.Original(s)
			if e != nil {
				w.err = e
				return
			}

			observers.Network(value, at)
		}
	}

	if observers.Secret != nil {
		w.observeSecret = func(s source.Span) {
			at, e := w.view.Original(s)
			if e != nil {
				w.err = e
				return
			}

			observers.Secret(at)
		}
	}

	if observers.Capability != nil {
		w.observeCapability = func(kind string, span source.Span) {
			at, err := w.view.Original(span)
			if err != nil {
				w.err = err
				return
			}

			observers.Capability(kind, at)
		}
	}

	if observers.DNS != nil {
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

			observers.DNS(query)
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
	if a.observeNetwork == nil && a.observeCapability == nil {
		return
	}

	r := wgetRequest{}
	for i := 0; i < len(args); i++ {
		next, valid := r.argument(args, i)
		if !valid {
			if a.observeNetwork != nil {
				a.observeNetwork("", c.Span)
			}

			return
		}

		if a.observeNetwork != nil && wgetOption(args[i]) == wgetOperand && httpURL(args[i].text) {
			a.observeNetwork(args[i].text, c.Span)
		}

		i = next
	}

	if r.remote {
		a.capability("untrusted_input", c.Span)
	}
}
