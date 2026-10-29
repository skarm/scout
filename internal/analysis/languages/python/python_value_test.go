package python //nolint:testpackage // Tests exercise private value graphs, aliases and bounded merges.

import (
	"testing"

	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestForkSeparatesMutableContentsAndPreservesAliases(t *testing.T) {
	mapping := &pyMapping{entries: map[string]pyValue{}}
	value := pyValue{meaning: mapping}
	mapping.entries["self"] = value
	instance := &pyInstance{fields: map[string]pyValue{"config": value}}
	function := &pyFunction{}
	bound := functionValue(function).bind(instanceValue(instance))
	sequence := pyValue{meaning: &pySequence{items: []pyValue{value, instanceValue(instance)}}}
	original := newPyState()
	original.names = map[string]pyValue{
		"one":            value,
		"two":            value,
		"receiver":       instanceValue(instance),
		"method":         bound,
		"sequence":       sequence,
		"sequence_alias": sequence,
	}
	fork := original.fork()
	cloned := fork.names["one"].mapping()
	if cloned == mapping || cloned != fork.names["two"].mapping() || cloned.entries["self"].mapping() != cloned {
		t.Fatal("fork lost a container cycle or alias, or shares mutable contents")
	}
	receiver := fork.names["receiver"].instance()
	method := fork.names["method"]
	boundReceiver := method.bound()
	if receiver == nil || receiver == instance || method.function() != function || boundReceiver == nil || boundReceiver.instance() != receiver || receiver.fields["config"].mapping() != cloned {
		t.Fatal("fork changed method identity or detached the bound receiver from its aliases")
	}
	items := fork.names["sequence"].elements()
	if items[0].mapping() != cloned || items[1].instance() != receiver || &items[0] != &fork.names["sequence_alias"].elements()[0] {
		t.Fatal("fork lost sequence element aliases")
	}
	cloned.entries["new"] = namedValue("new")
	if _, exists := mapping.entries["new"]; exists {
		t.Fatal("hypothetical branch mutated the original mapping")
	}
}

func TestBranchMergeKeepsOneMeaningAndIndependentTaint(t *testing.T) {
	left := namedValue("os.system")
	left.origins = []pyOrigin{{kind: "input", start: 1, end: 2}}
	right := namedValue("os.system")
	right.origins = []pyOrigin{{kind: "environment", start: 3, end: 4}}
	if merged := mergePyValue(left, right); merged.symbol() != "os.system" || len(merged.origins) != 2 {
		t.Fatal("compatible symbol lost identity or branch taint")
	}
	if merged := mergePyValue(left, classValue(&pyClass{})); merged.meaning != nil || len(merged.origins) != 1 {
		t.Fatal("incompatible meanings were combined or taint was discarded")
	}
	empty := literalValue("", true, 1)
	if text, known := mergePyValue(empty, empty).literal(); !known || text != "" {
		t.Fatal("known empty literal became unknown")
	}
	if _, known := mergePyValue(empty, pyValue{}).literal(); known {
		t.Fatal("unknown branch became a known literal")
	}
	function := &pyFunction{}
	callable := functionValue(function)
	a, b := callable.bind(classValue(&pyClass{})), callable.bind(classValue(&pyClass{}))
	merged := mergePyValue(a, b)
	boundReceiver := merged.bound()
	if merged.function() != function || boundReceiver == nil || boundReceiver.meaning != nil {
		t.Fatal("different possible receivers lost known boundness or became one definite receiver")
	}
}

func TestMappingBranchMergeRetainsCycleAndJoinsContentTaint(t *testing.T) {
	a, b := &pyMapping{entries: map[string]pyValue{}}, &pyMapping{entries: map[string]pyValue{}}
	x, y := pyValue{meaning: a}, pyValue{meaning: b}
	a.entries["self"], b.entries["self"] = x, y
	a.entries["value"] = pyValue{origins: []pyOrigin{{kind: "input", start: 1, end: 2}}}
	b.entries["value"] = pyValue{origins: []pyOrigin{{kind: "environment", start: 3, end: 4}}}
	merged := pyContents(mergePyValue(x, y))
	if merged.mapping() == a || merged.mapping() == b || merged.mapping().entries["self"].mapping() != merged.mapping() || len(merged.origins) != 2 {
		t.Fatal("branch merge lost cyclic identity or current content taint")
	}
}

func TestTransformKeepsCallableIdentityAndOwnsTrace(t *testing.T) {
	function := &pyFunction{}
	value := functionValue(function).bind(classValue(&pyClass{}))
	value.origins = []pyOrigin{{kind: "input", start: 0, end: 1}}
	transformed := transformed(value, &frontend.Node{Start: 4, End: 8})
	if transformed.function() != function || transformed.bound() != value.bound() || len(transformed.origins[0].steps) != 1 || len(value.origins[0].steps) != 0 {
		t.Fatal("source transformation changed semantic identity or shared mutable trace")
	}
}
