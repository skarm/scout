package securitytext

import (
	"context"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

// VariationCarriers reports repeated selectors, including invalid UTF-8
// payloads. A single selector after an emoji or ideograph is not a payload run.
func VariationCarriers(ctx context.Context, text string) ([]source.Span, bool) {
	if len(text) > MaxBytes {
		return nil, true
	}

	var spans []source.Span

	count := 0

	for at := 0; at < len(text); {
		if ctx.Err() != nil {
			return spans, true
		}

		r, n := utf8.DecodeRuneInString(text[at:])
		if !variationSelector(r) {
			at += n
			continue
		}

		start, run := at, 0
		for at < len(text) {
			r, n = utf8.DecodeRuneInString(text[at:])
			if !variationSelector(r) {
				break
			}

			run++

			count++
			if count > MaxChanges || ctx.Err() != nil {
				return spans, true
			}

			at += n
		}

		if run >= 2 {
			spans = append(spans, source.Span{Start: start, End: at})
		}
	}

	return spans, false
}

// Encoded carriers are interpreted as data only. Both the raw and the old
// control-stripped views remain inspected. Decoded bytes are never executed,
// logged or supplied as trusted instructions to a reviewer.
func encodedReplacements(ctx context.Context, text string) ([]source.Replacement, bool) {
	var out []source.Replacement

	count := 0

	for at := 0; at < len(text); {
		if ctx.Err() != nil {
			return out, true
		}

		r, n := utf8.DecodeRuneInString(text[at:])

		kind := carrierKind(r)
		if kind == 0 {
			at += n
			continue
		}

		start := at

		var decoded []byte

		for at < len(text) {
			r, n = utf8.DecodeRuneInString(text[at:])
			if carrierKind(r) != kind {
				break
			}

			count++
			if count > MaxChanges || ctx.Err() != nil {
				return out, true
			}

			if kind == 1 {
				if r >= 0xe0020 && r <= 0xe007e {
					decoded = append(decoded, byte(r-0xe0000))
				} else if r == 0xe007f {
					decoded = append(decoded, ' ')
				}
			} else if r <= 0xfe0f {
				decoded = append(decoded, byte(r-0xfe00)) //nolint:gosec // G115: carrierKind established FE00..FE0F; the value is 0..15.
			} else {
				decoded = append(decoded, byte(r-0xe0100+16)) //nolint:gosec // G115: carrierKind established E0100..E01EF; the value is 16..255.
			}

			at += n
		}

		if len(decoded) > 0 && (kind == 1 || len(decoded) >= 2) && utf8.Valid(decoded) {
			out = append(out, source.Replacement{Span: source.Span{Start: start, End: at}, Text: string(decoded)})
		}
	}

	return out, false
}

func carrierKind(r rune) int {
	if r >= 0xe0000 && r <= 0xe007f {
		return 1
	}

	if variationSelector(r) {
		return 2
	}

	return 0
}
