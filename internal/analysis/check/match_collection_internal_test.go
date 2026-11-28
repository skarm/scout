package check

import "testing"

func TestMatchCollectionRetainsOnlyAdmittedSpans(t *testing.T) {
	var out Result
	collector := NewMatchCollector(&out, 1)
	if !collector.Span(0, 1) || collector.Span(1, 2) || !collector.Span(0, 1) {
		t.Fatal("collection changed distinct admission or deduplication")
	}
	for start := 2; start < 128; start++ {
		if collector.Span(start, start+1) {
			t.Fatal("collection admitted an observation after the limit")
		}
	}
	if len(collector.seen) != 1 || len(out.Matches) != 1 || !out.Truncated {
		t.Fatalf("rejected matches consumed retention state: seen=%d result=%+v", len(collector.seen), out)
	}
}
