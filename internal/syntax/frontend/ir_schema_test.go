package frontend //nolint:testpackage // Tests exercise private node constructors and schema validation.

import (
	"encoding/json"
	"testing"
)

func TestPythonIRRejectsUnknownAndMismatchedShapes(t *testing.T) {
	for _, raw := range []string{
		`{"type":"NotPython","start":0,"end":1}`,
		`{"type":"Name","start":0,"end":1,"fields":{"value":"x"}}`,
		`{"type":"Name","start":0,"end":1,"fields":{"id":true}}`,
		`{"type":"Call","start":0,"end":1,"fields":{"args":["x"]}}`,
		`{"type":"Call","start":0,"end":1,"fields":{"surprise":{"type":"Name","start":0,"end":1}}}`,
		`{"type":"Name","start":0,"end":1,"fields":{"id":"x","id":"y"}}`,
		`{"type":"Name","type":"Call","start":0,"end":1}`,
		`{"type":"Name","start":0,"end":1,"extra":true}`,
		`{"type":"Name","start":null,"end":1}`,
		`{"type":"Name","start":0,"end":1,"fields":null}`,
	} {
		t.Run(raw, func(t *testing.T) {
			node := newNode(Name, 3, 5)
			if err := json.Unmarshal([]byte(raw), &node); err == nil {
				t.Fatalf("accepted invalid Python IR: %s", raw)
			}
			if node.Kind() != Name || node.Start != 3 || node.End != 5 || len(node.fields) != 0 {
				t.Fatal("failed decode partially replaced node")
			}
		})
	}
}

func TestNodeConstructionRejectsInvalidChildAndOwnsFieldOrder(t *testing.T) {
	if _, err := NewNode(Call, 0, 1, ChildField(Func, &Node{})); err == nil {
		t.Fatal("accepted a child without a known node kind")
	}
	if _, err := NewNode(Call, 0, 1, NodesField(Args, []*Node{{Start: 0, End: 1}})); err == nil {
		t.Fatal("accepted an unvalidated child in a list")
	}
	function := newNode(Name, 0, 1)
	argument := newNode(Name, 2, 3)
	call, err := NewNode(Call, 0, 4, NodesField(Args, []*Node{argument}), ChildField(Func, function))
	if err != nil {
		t.Fatal(err)
	}
	if children := call.Children(); len(children) != 2 || children[0] != function || children[1] != argument {
		t.Fatal("construction order changed AST traversal order")
	}
	if _, err := NewNode(Name, 0, 1, TextField(ID, "x"), TextField(ID, "y")); err == nil {
		t.Fatal("accepted duplicate structural selector")
	}
}
