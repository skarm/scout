package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//nolint:gochecknoglobals // The mutex protects cached immutable field metadata; reports are never retained.
var canonicalFields = struct {
	sync.RWMutex
	values map[reflect.Type][]canonicalField
}{values: make(map[reflect.Type][]canonicalField)}

type canonicalField struct {
	index int
	name  string
	key   []byte
	empty bool
	zero  bool
}

// Reports are passive Go values. Copy their ownership directly instead of
// decoding their wire representation back into a second object graph.
func copyReportValue(v reflect.Value) reflect.Value {
	out := reflect.New(v.Type()).Elem()
	out.Set(v)
	copyReportReferences(out)

	return out
}

// Copy value fields in bulk; only reference fields need independent storage.
// Walking addressable children avoids allocating a temporary for every DTO.
func copyReportReferences(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}

		out := reflect.New(v.Type().Elem())
		out.Elem().Set(v.Elem())
		copyReportReferences(out.Elem())
		v.Set(out)
	case reflect.Struct:
		for _, field := range v.Fields() {
			copyReportReferences(field)
		}
	case reflect.Slice:
		if v.IsNil() {
			return
		}

		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(out, v)

		for i := range v.Len() {
			copyReportReferences(out.Index(i))
		}

		v.Set(out)
	default:
		// Scalar fields have already been copied by the caller.
		return
	}
}

func copyReport[T any](value T) T {
	var snapshot T
	reflect.ValueOf(&snapshot).Elem().Set(copyReportValue(reflect.ValueOf(value)))

	return snapshot
}

func fieldsFor(t reflect.Type) []canonicalField {
	canonicalFields.RLock()
	cached, ok := canonicalFields.values[t]
	canonicalFields.RUnlock()

	if ok {
		return cached
	}

	fields := make([]canonicalField, 0, t.NumField())
	for i := range t.NumField() {
		field := t.Field(i)

		tags := strings.Split(field.Tag.Get("json"), ",")
		if field.PkgPath != "" || tags[0] == "-" {
			continue
		}

		name := tags[0]
		if name == "" {
			name = field.Name
		}

		key, _ := json.Marshal(name)

		f := canonicalField{index: i, name: name, key: append(key, ':')}
		for _, option := range tags[1:] {
			f.empty = f.empty || option == "omitempty"
			f.zero = f.zero || option == "omitzero"
		}

		fields = append(fields, f)
	}

	sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	canonicalFields.Lock()
	canonicalFields.values[t] = fields
	canonicalFields.Unlock()

	return fields
}

// canonicalValue writes the same sorted-key JSON domain used by run digests,
// directly from its concrete DTOs. No map[string]any or JSON round trip exists.
func canonicalValue(out []byte, value reflect.Value, field string) ([]byte, error) {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return append(out, "null"...), nil
		}

		return canonicalValue(out, value.Elem(), field)
	case reflect.Struct:
		return canonicalStruct(out, value)
	case reflect.Slice, reflect.Array:
		return canonicalSequence(out, value, field)
	default:
		return canonicalScalar(out, value)
	}
}

// Scalar tokens have no field ordering or collection semantics. Keep their
// closed domain explicit; arbitrary MarshalJSON methods must not affect digests.
func canonicalScalar(out []byte, value reflect.Value) ([]byte, error) {
	switch value.Kind() {
	case reflect.String:
		text := value.String()
		// Printable ASCII needs no JSON escaping. Keep encoding/json as the
		// oracle for controls, HTML escaping, Unicode and invalid UTF-8.
		plain := true

		for i := range len(text) {
			c := text[i]
			if c < 0x20 || c >= 0x80 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
				plain = false
				break
			}
		}

		if plain {
			out = append(out, '"')
			out = append(out, text...)

			return append(out, '"'), nil
		}

		encoded, err := json.Marshal(text)

		return append(out, encoded...), err
	case reflect.Bool:
		return strconv.AppendBool(out, value.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.AppendInt(out, value.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.AppendUint(out, value.Uint(), 10), nil
	default:
		return nil, fmt.Errorf("unsupported report value %s", value.Type())
	}
}

func canonicalStruct(out []byte, value reflect.Value) ([]byte, error) {
	out = append(out, '{')
	count := 0

	for _, field := range fieldsFor(value.Type()) {
		child := value.Field(field.index)
		if field.zero && child.IsZero() || field.empty && emptyJSONValue(child) {
			continue
		}

		if count > 0 {
			out = append(out, ',')
		}

		count++

		out = append(out, field.key...)

		var err error

		out, err = canonicalValue(out, child, field.name)
		if err != nil {
			return nil, err
		}
	}

	return append(out, '}'), nil
}

func emptyJSONValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Slice, reflect.Array, reflect.String:
		return value.Len() == 0
	default:
		return value.IsZero()
	}
}

func canonicalSequence(out []byte, value reflect.Value, field string) ([]byte, error) {
	if value.Kind() == reflect.Slice && value.IsNil() && !unorderedCollection(field) {
		return append(out, "null"...), nil
	}

	out = append(out, '[')
	if unorderedCollection(field) {
		return canonicalSet(out, value)
	}

	return canonicalOrdered(out, value)
}

func canonicalSet(out []byte, value reflect.Value) ([]byte, error) {
	if value.Len() == 0 {
		return append(out, ']'), nil
	}
	// Encode into the destination. Offsets survive growth, and already sorted
	// collections need no second buffer. Only reordered bytes need a scratch copy.
	type span struct{ start, end int }

	items := make([]span, value.Len())
	start := len(out)

	for i := range value.Len() {
		var err error

		if i > 0 {
			out = append(out, ',')
		}

		itemStart := len(out) - start

		out, err = canonicalValue(out, value.Index(i), "")
		if err != nil {
			return nil, err
		}

		items[i] = span{start: itemStart, end: len(out) - start}
	}

	encoded := out[start:]

	less := func(i, j int) bool {
		a, b := items[i], items[j]
		return bytes.Compare(encoded[a.start:a.end], encoded[b.start:b.end]) < 0
	}
	if sort.SliceIsSorted(items, less) {
		return append(out, ']'), nil
	}

	encoded = bytes.Clone(encoded)

	sort.Slice(items, less)

	out = out[:start]

	for i, item := range items {
		if i > 0 {
			out = append(out, ',')
		}

		out = append(out, encoded[item.start:item.end]...)
	}

	return append(out, ']'), nil
}

func canonicalOrdered(out []byte, value reflect.Value) ([]byte, error) {
	for i := range value.Len() {
		if i > 0 {
			out = append(out, ',')
		}

		var err error

		out, err = canonicalValue(out, value.Index(i), "")
		if err != nil {
			return nil, err
		}
	}

	return append(out, ']'), nil
}
