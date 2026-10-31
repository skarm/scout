package evaluation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"
)

// The typed decoder rejects fields in the wrong location. This first pass also
// rejects duplicate keys and Go's case-insensitive field aliases.
func validateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid corpus UTF-8")
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()

	if err := jsonValue(d, 0, ""); err != nil {
		return err
	}

	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing corpus data")
	}

	return nil
}

func jsonValue(d *json.Decoder, depth int, field string) error {
	if depth > 8 {
		return errors.New("corpus nesting exceeds limit")
	}

	token, err := d.Token()
	if err != nil {
		return errors.New("invalid corpus JSON")
	}

	if token == nil && !slices.Contains([]string{"expected_rules", "files", "sources"}, field) {
		return errors.New("null corpus value is not allowed")
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	seen := map[string]bool{}
	packageFile := delim == '{' && field == "files"

	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid corpus object")
			}

			name, ok := key.(string)
			if !ok || seen[name] || !slices.Contains([]string{"schema_version", "kind", "cases", "sources", "id", "category", "label", "path", "content", "expected_rules", "files", "source_id", "split", "executable", "origin", "revision", "license", "label_review"}, name) {
				return errors.New("unknown or duplicate corpus field")
			}

			seen[name] = true
			field = name
		}

		if err := jsonValue(d, depth+1, field); err != nil {
			return err
		}
	}

	if packageFile && (!seen["path"] || !seen["content"]) {
		return errors.New("package files require explicit path and content")
	}

	_, err = d.Token()

	return err
}
