package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
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
		// Fields also builds unused StructField metadata for every value.
		// Keep this recursive value-only walk free of those allocations.
		for i := range v.NumField() {
			copyReportReferences(v.Field(i))
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

const canonicalChunkSize = 64 << 10

// canonicalValue writes the same sorted-key JSON domain used by run digests,
// directly from its concrete DTOs. No map[string]any or JSON round trip exists.
// Ordered traversal can flush completed bytes before encoding the next value.
func canonicalValue(out []byte, value reflect.Value, field string, flush func([]byte) []byte) ([]byte, error) {
	if len(out) >= canonicalChunkSize && flush != nil {
		out = flush(out)
	}

	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return append(out, "null"...), nil
		}

		return canonicalValue(out, value.Elem(), field, flush)
	case reflect.Struct:
		return canonicalStruct(out, value, flush)
	case reflect.Slice, reflect.Array:
		return canonicalSequence(out, value, field, flush)
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
		// oracle for controls, HTML escaping and valid Unicode.
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

		// Match the original Marshal -> Decode -> Marshal digest domain.
		// Invalid bytes become individual replacement runes before encoding;
		// normalization keeps their spelling independent of the Go toolchain.
		if !utf8.ValidString(text) {
			text = string([]rune(text))
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

func canonicalStruct(out []byte, value reflect.Value, flush func([]byte) []byte) ([]byte, error) {
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

		out, err = canonicalValue(out, child, field.name, flush)
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

func canonicalSequence(out []byte, value reflect.Value, field string, flush func([]byte) []byte) ([]byte, error) {
	if value.Kind() == reflect.Slice && value.IsNil() && !unorderedCollection(field) {
		return append(out, "null"...), nil
	}

	out = append(out, '[')
	if unorderedCollection(field) {
		return canonicalSet(out, value, flush)
	}

	return canonicalOrdered(out, value, flush)
}

func canonicalSet(out []byte, value reflect.Value, flush func([]byte) []byte) ([]byte, error) {
	if value.Len() < 2 {
		return canonicalOrdered(out, value, flush)
	}

	type span struct{ start, end int }

	items := make([]span, value.Len())
	start := len(out)

	for i := range value.Len() {
		var err error

		itemStart := len(out) - start

		// The complete collection must stay in memory until its bytes are sorted.
		out, err = canonicalValue(out, value.Index(i), "", nil)
		if err != nil {
			return nil, err
		}

		items[i] = span{start: itemStart, end: len(out) - start}
		// A stored comma allows the whole item and delimiter to be copied or
		// hashed together. The last item in the sorted order omits its comma.
		out = append(out, ',')

		if i == 0 {
			// Similar-sized records are common in reports. Reserve from the
			// first encoded item without a second reflective walk. Cap the
			// estimate so one unusually large item cannot multiply memory use.
			itemBytes := len(out) - start
			out = slices.Grow(out, min(value.Len()-1, (1<<20)/itemBytes)*itemBytes)
		}
	}

	encoded := out[start:]

	compare := func(a, b span) int {
		return bytes.Compare(encoded[a.start:a.end], encoded[b.start:b.end])
	}

	if slices.IsSortedFunc(items, compare) {
		return append(out[:len(out)-1], ']'), nil
	}

	slices.SortFunc(items, compare)

	if len(encoded) >= canonicalChunkSize && flush != nil {
		// Hash the sorted spans directly so large collections need no scratch copy.
		flush(out[:start])

		for i, item := range items {
			end := item.end
			if i < len(items)-1 {
				end++
			}

			flush(encoded[item.start:end])
		}

		return append(out[:0], ']'), nil
	}

	buffer := borrowCanonicalBuffer()
	defer releaseCanonicalBuffer(buffer)

	*buffer = append((*buffer)[:0], encoded...)

	out = out[:start]

	for i, item := range items {
		end := item.end
		if i < len(items)-1 {
			end++
		}

		out = append(out, (*buffer)[item.start:end]...)
	}

	return append(out, ']'), nil
}

func canonicalOrdered(out []byte, value reflect.Value, flush func([]byte) []byte) ([]byte, error) {
	for i := range value.Len() {
		if i > 0 {
			out = append(out, ',')
		}

		var err error

		out, err = canonicalValue(out, value.Index(i), "", flush)
		if err != nil {
			return nil, err
		}
	}

	return append(out, ']'), nil
}
