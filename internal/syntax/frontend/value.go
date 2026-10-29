//goland:noinspection GoMixedReceiverTypes // JSON values marshal by value and unmarshal by pointer.
package frontend

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"unicode/utf8"
)

// ValueKind distinguishes the closed set of Python IR field shapes.
type valueKind uint8

const (
	ValueNull valueKind = iota
	ValueString
	ValueBool
	ValueInteger
	ValueNumber
	valueBytes
	valueNode
	valueNodes
	valueStrings
)

// Value keeps an IR field in Go memory. Its zero value is explicit null; a
// missing field is distinguished by its absence from the containing node.
// Nodes and slice views are read-only after the preparation pass completes.
type Value struct {
	child    *Node
	text     string
	bytes    []byte
	children []*Node
	strings  []string
	integer  int64
	kind     valueKind
	boolean  bool
}

func NullValue() Value               { return Value{} }
func StringValue(value string) Value { return Value{kind: ValueString, text: value} }
func BoolValue(value bool) Value     { return Value{kind: ValueBool, boolean: value} }
func BytesValue(value []byte) Value  { return Value{kind: valueBytes, bytes: slices.Clone(value)} }
func childValue(value *Node) Value {
	if value == nil {
		return NullValue()
	}

	return Value{kind: valueNode, child: value}
}

func nodesValue(value []*Node) Value { return Value{kind: valueNodes, children: slices.Clone(value)} }

func stringsValue(value []string) Value {
	return Value{kind: valueStrings, strings: slices.Clone(value)}
}

func integerValue(value int64) Value { return Value{kind: ValueInteger, integer: value} }

func numberValue(value string) (Value, error) {
	if value == "" || value[0] != '-' && (value[0] < '0' || value[0] > '9') || !json.Valid([]byte(value)) {
		return Value{}, errors.New("invalid Python IR number")
	}

	return Value{kind: ValueNumber, text: value}, nil
}

func hexValue(encoded string) (Value, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return Value{}, errors.New("invalid Python IR byte literal")
	}

	return Value{kind: valueBytes, bytes: data}, nil
}

func (v Value) Kind() valueKind { return v.kind }

func (v Value) Text() (string, bool) {
	if v.kind == ValueString {
		return v.text, true
	}

	return "", false
}

func (v Value) Boolean() (bool, bool) { return v.boolean, v.kind == ValueBool }

func (v Value) Integer() (int64, bool) { return v.integer, v.kind == ValueInteger }

func (v Value) Number() (json.Number, bool) {
	if v.kind == ValueNumber {
		return json.Number(v.text), true
	}

	return "", false
}

func (v Value) byteSlice() ([]byte, bool) { return v.bytes, v.kind == valueBytes }

func (v Value) node() *Node {
	if v.kind == valueNode {
		return v.child
	}

	return nil
}

func (v Value) nodeSlice() []*Node {
	if v.kind == valueNodes {
		return v.children
	}

	return nil
}

func (v Value) Strings() ([]string, bool) {
	if v.kind == valueStrings {
		return v.strings, true
	}

	return nil, false
}

// MarshalJSON preserves the legacy field representation at a transport boundary.
// The analyzer and normalizer use the typed accessors and never call this method.
func (v Value) MarshalJSON() ([]byte, error) {
	switch v.kind {
	case ValueNull:
		return []byte("null"), nil
	case ValueString:
		return json.Marshal(v.text)
	case ValueBool:
		return []byte(strconv.FormatBool(v.boolean)), nil
	case ValueInteger:
		return []byte(strconv.FormatInt(v.integer, 10)), nil
	case ValueNumber:
		return json.Marshal(json.Number(v.text))
	default:
		return v.marshalComposite()
	}
}

// UnmarshalJSON changes the value only after its entire field has been decoded.
func (v *Value) UnmarshalJSON(data []byte) error {
	if v == nil {
		return errors.New("nil Python IR value receiver")
	}

	decoded, err := decodeValue(data)
	if err != nil {
		return err
	}

	*v = decoded

	return nil
}

func (v Value) marshalComposite() ([]byte, error) {
	switch v.kind {
	case valueBytes:
		return json.Marshal(map[string]string{"bytes_hex": hex.EncodeToString(v.bytes)})
	case valueNode:
		return json.Marshal(v.child)
	case valueNodes:
		if v.children == nil {
			return []byte("[]"), nil
		}

		return json.Marshal(v.children)
	case valueStrings:
		if v.strings == nil {
			return []byte("[]"), nil
		}

		return json.Marshal(v.strings)
	default:
		return nil, errors.New("invalid Python IR field kind")
	}
}

func decodeValue(data []byte) (Value, error) {
	data = bytes.TrimSpace(data)
	if err := validateValueEncoding(data); err != nil {
		return Value{}, err
	}

	switch data[0] {
	case 'n':
		return Value{}, nil
	case 't', 'f':
		return Value{kind: ValueBool, boolean: data[0] == 't'}, nil
	case '"':
		return decodeTextValue(data)
	case '{':
		return decodeObjectValue(data)
	case '[':
		return decodeArrayValue(data)
	default:
		return decodeNumberValue(data)
	}
}

func validateValueEncoding(data []byte) error {
	if len(data) == 0 || !utf8.Valid(data) || !json.Valid(data) {
		return errors.New("invalid Python IR field JSON")
	}

	return nil
}

func decodeTextValue(data []byte) (Value, error) {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return Value{}, err
	}

	return StringValue(text), nil
}

func decodeNumberValue(data []byte) (Value, error) {
	if integer, err := strconv.ParseInt(string(data), 10, 64); err == nil {
		return integerValue(integer), nil
	}

	return numberValue(string(data))
}

func decodeObjectValue(data []byte) (Value, error) {
	fields, err := valueObjectFields(data)
	if err != nil {
		return Value{}, err
	}

	if encoded, ok := fields["bytes_hex"]; ok && len(fields) == 1 {
		var text string
		if len(encoded) == 0 || encoded[0] != '"' || json.Unmarshal(encoded, &text) != nil {
			return Value{}, errors.New("invalid Python IR byte literal")
		}

		return hexValue(text)
	}

	node, err := decodeNodeObject(fields)
	if err != nil {
		return Value{}, err
	}

	return childValue(node), nil
}

func valueObjectFields(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	if first != json.Delim('{') {
		return nil, errors.New("python IR object required")
	}

	fields := map[string]json.RawMessage{}
	for decoder.More() {
		if err := readObjectEntry(decoder, fields); err != nil {
			return nil, err
		}
	}

	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.More() {
		return nil, errors.New("invalid Python IR object ending")
	}

	return fields, nil
}

func readObjectEntry(decoder *json.Decoder, fields map[string]json.RawMessage) error {
	key, err := decoder.Token()
	if err != nil {
		return err
	}

	name, ok := key.(string)
	if !ok {
		return errors.New("invalid Python IR object key")
	}

	if _, exists := fields[name]; exists {
		return errors.New("duplicate Python IR object key")
	}

	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return err
	}

	fields[name] = value

	return nil
}

func decodeArrayValue(data []byte) (Value, error) {
	var fields []json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return Value{}, err
	}

	if len(fields) > 0 && fields[0][0] == '"' {
		return decodeStringList(fields)
	}

	return decodeNodeList(fields)
}

func decodeStringList(fields []json.RawMessage) (Value, error) {
	names := make([]string, len(fields))
	for i, field := range fields {
		if len(field) == 0 || field[0] != '"' || json.Unmarshal(field, &names[i]) != nil {
			return Value{}, errors.New("mixed Python IR string list")
		}
	}

	return stringsValue(names), nil
}

func decodeNodeList(fields []json.RawMessage) (Value, error) {
	children := make([]*Node, len(fields))
	for i, field := range fields {
		value, err := decodeValue(field)
		if err != nil {
			return Value{}, err
		}

		if value.kind != ValueNull && value.kind != valueNode {
			return Value{}, errors.New("invalid Python IR node list")
		}

		children[i] = value.child
	}

	return Value{kind: valueNodes, children: children}, nil
}
