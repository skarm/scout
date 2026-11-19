package extract

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const MaxJSONDepth = 64

type jsonProgress struct {
	depth, ordinal   int
	finished         bool
	skipped          bool
	skippedContainer bool
}

func jsonCandidate(name, data string) bool {
	if strings.EqualFold(path.Ext(name), ".json") {
		return true
	}
	// Conservative content hint, not a promise to find every embedded JSON value.
	s := strings.TrimSpace(data)
	if len(s) < 2 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return false
	}

	if s[0] != '{' && s[0] != '[' {
		return false
	}

	tail := strings.TrimSpace(s[1:])

	return strings.HasPrefix(tail, "\"") || strings.HasPrefix(tail, "{")
}

// Stream tokens instead of building an unbounded map/interface tree. Both keys
// and values are inspected; field names cannot turn off extraction. Token IDs,
// not actual key/value strings, are used in provenance to avoid secret leakage.
func extractJSON(o *operation) error {
	text := o.parent.file.Content()
	decoder := json.NewDecoder(contextReader{ctx: o.b.ctx, r: strings.NewReader(text)})
	decoder.UseNumber()

	state := jsonProgress{}

	for !state.finished {
		if err := o.entry(); err != nil {
			return err
		}

		start := int(decoder.InputOffset())

		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return errFormat
		}

		if err != nil {
			return err
		}

		end := int(decoder.InputOffset())

		if err := state.consume(o, token, report.ByteRange{Start: start, End: end}, text[start:end]); err != nil {
			return err
		}

		state.ordinal++
	}

	// The document is complete at the final token. EOF or trailing
	// whitespace does not consume a container entry.
	if strings.Trim(text[decoder.InputOffset():], " \r\n\t") != "" {
		return errFormat
	}

	if state.skipped {
		o.skippedNonContainers = !state.skippedContainer
		return errBudget
	}

	return o.b.ctx.Err()
}

func (s *jsonProgress) consume(o *operation, token any, span report.ByteRange, raw string) error {
	var err error

	switch value := token.(type) {
	case json.Delim:
		s.depth, s.finished, err = jsonDelimiterDepth(value, s.depth)
		if err != nil {
			return err
		}
	case string:
		err = extractJSONString(o, value, s.ordinal, span, raw)
		if errors.Is(err, errBudget) {
			s.skipped = true
			s.skippedContainer = s.skippedContainer || mayDecodeContainer(value)
		} else if err != nil {
			return err
		}

		if s.depth == 0 {
			s.finished = true
		}
	default:
		if s.depth == 0 {
			s.finished = true
		}
	}

	return nil
}

func jsonDelimiterDepth(value json.Delim, depth int) (int, bool, error) {
	switch value {
	case '{', '[':
		depth++
		if depth > MaxJSONDepth {
			return depth, false, errBudget
		}
	case '}', ']':
		depth--
		if depth < 0 {
			return depth, false, errFormat
		}

		return depth, depth == 0, nil
	}

	return depth, false, nil
}

func extractJSONString(o *operation, value string, ordinal int, span report.ByteRange, raw string) error {
	// encoding/json substitutes U+FFFD for invalid Unicode. Validate the actual
	// bytes so malformed escapes cannot be mistaken for literal U+FFFD.
	quote := strings.IndexByte(raw, '"')
	if quote < 0 || !jsonconfig.ValidStringUnicode(raw[quote:]) {
		return errFormat
	}

	return o.text(fmt.Sprintf("json-string-%d.txt", ordinal), value, &span)
}
