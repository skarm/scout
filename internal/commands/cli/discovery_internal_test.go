package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/skarm/scout/internal/discovery"
)

func TestInventoryPublicationCannotReplaceDiscoveryErrorWithSuccess(t *testing.T) {
	a := discoveryArguments{format: "json"}
	snapshot := discovery.Snapshot{
		Schema: "scout.environment/v1", Complete: true,
		Components: []discovery.Component{{Kind: "skill", Name: "retained"}},
	}
	var out, diagnostics bytes.Buffer
	code := a.publishInventory(context.Background(), snapshot, context.DeadlineExceeded, &out, &diagnostics)
	var published discovery.Snapshot
	if code != 2 || json.Unmarshal(out.Bytes(), &published) != nil || published.Complete || len(published.Components) != 1 {
		t.Fatalf("publication hid discovery failure: code=%d output=%s diagnostics=%s", code, &out, &diagnostics)
	}
}
