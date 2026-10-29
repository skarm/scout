package frontend //nolint:testpackage // Tests exercise private numeric literals and sealed node constructors.

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestValuePreservesTypedFields(t *testing.T) {
	node := newNode(Name, 0, 1)
	number, err := numberValue("1.25e2")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		value Value
		kind  valueKind
	}{
		{name: "null", value: NullValue(), kind: ValueNull},
		{name: "string", value: StringValue("secret"), kind: ValueString},
		{name: "bool", value: BoolValue(true), kind: ValueBool},
		{name: "integer", value: integerValue(3), kind: ValueInteger},
		{name: "number", value: number, kind: ValueNumber},
		{name: "bytes", value: BytesValue([]byte{0xff, 0}), kind: valueBytes},
		{name: "child", value: childValue(node), kind: valueNode},
		{name: "children", value: nodesValue([]*Node{node, nil, node}), kind: valueNodes},
		{name: "names", value: stringsValue([]string{"global_name"}), kind: valueStrings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value.Kind() != tc.kind {
				t.Fatalf("kind=%v, want %v", tc.value.Kind(), tc.kind)
			}
			encoded, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeValue(encoded)
			if err != nil {
				t.Fatalf("decode %s: %v", encoded, err)
			}
			again, err := json.Marshal(decoded)
			if err != nil || string(again) != string(encoded) || decoded.Kind() != tc.kind {
				t.Fatalf("round trip %s => %s: kind=%v err=%v", encoded, again, decoded.Kind(), err)
			}
		})
	}
	if text, ok := StringValue("secret").Text(); !ok || text != "secret" {
		t.Fatal(text, ok)
	}
	if truth, ok := BoolValue(false).Boolean(); !ok || truth {
		t.Fatal(truth, ok)
	}
	if integer, ok := integerValue(-3).Integer(); !ok || integer != -3 {
		t.Fatal(integer, ok)
	}
	if value, ok := number.Number(); !ok || value != "1.25e2" {
		t.Fatal(value, ok)
	}
	if childValue(node).node() != node {
		t.Fatal("child identity changed")
	}
}

func TestValueRejectsTypeConfusionAndCopiesBoundarySlices(t *testing.T) {
	var null Value
	if _, ok := null.Text(); ok {
		t.Fatal("null became a string")
	}
	if _, ok := null.Boolean(); ok {
		t.Fatal("null became false")
	}
	if _, ok := null.Integer(); ok {
		t.Fatal("null became zero")
	}
	numeric, _ := numberValue("1.25e2")
	if _, ok := numeric.Text(); ok {
		t.Fatal("number became a string")
	}
	if _, ok := StringValue("not a number").Number(); ok {
		t.Fatal("string became a number")
	}
	node := newNode(Name, 0, 1)
	input := []*Node{node, nil}
	value := nodesValue(input)
	input[0] = nil
	if got := value.nodeSlice(); len(got) != 2 || got[0] != node || got[1] != nil {
		t.Fatal("caller changed captured node list")
	}
	inputBytes := []byte{0xff, 0}
	bytesValue := BytesValue(inputBytes)
	inputBytes[0] = 0
	if got, ok := bytesValue.byteSlice(); !ok || !reflect.DeepEqual(got, []byte{0xff, 0}) {
		t.Fatal(got, ok)
	}
	inputNames := []string{"one"}
	names := stringsValue(inputNames)
	inputNames[0] = "changed"
	if got, ok := names.Strings(); !ok || got[0] != "one" {
		t.Fatal("caller changed captured names")
	}
	if _, ok := nodesValue(nil).Strings(); ok {
		t.Fatal("node list became string list")
	}
}

func TestValueBytesAndEmptyArraysHaveExplicitBoundaryShapes(t *testing.T) {
	value, err := decodeValue([]byte(`{"bytes_hex":"ff00"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.byteSlice(); !ok || !reflect.DeepEqual(got, []byte{0xff, 0}) {
		t.Fatal(got, ok)
	}
	value, err = decodeValue([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if value.Kind() != valueNodes || len(value.nodeSlice()) != 0 {
		t.Fatal("untyped wire array was not decoded as a node list")
	}
	var global Node
	if err := json.Unmarshal([]byte(`{"type":"Global","start":0,"end":1,"fields":{"names":[]}}`), &global); err != nil {
		t.Fatal(err)
	}
	if names, ok := global.Field(Names).Strings(); !ok || len(names) != 0 {
		t.Fatal("schema did not resolve empty declaration-name list")
	}
}

func TestValueRejectsUnknownAndAmbiguousTransport(t *testing.T) {
	for _, raw := range []string{`{"unknown":1}`, `{"bytes_hex":"ff","extra":1}`, `{"bytes_hex":"ff","bytes_hex":"00"}`, `{"bytes_hex":"zz"}`, `{"type":"Name","unknown":1}`, `{"type":""}`, `[1]`, `["x",null]`, `true false`} {
		if _, err := decodeValue([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, number := range []string{"", "NaN", "Infinity", "null", "+1", "1 2"} {
		if _, err := numberValue(number); err == nil {
			t.Fatalf("accepted number %q", number)
		}
	}
}
