package shell

import (
	"context"
	"errors"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

// ObserveNetwork uses the same native command/option grammar as SH001/SH002.
// Callbacks contain captured text for trusted analysis only, never public logs.
func ObserveNetwork(ctx context.Context, doc document.File, network func(string, source.Span), secret func(source.Span)) error {
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
	w.units(doc.Units())

	return errors.Join(w.err, w.gap, ctx.Err())
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
