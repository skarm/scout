package cli

import (
	"encoding/json"
	"io"

	"github.com/skarm/scout"
)

func profilesCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		return usageError(stderr, "use config validate to inspect a configured profile")
	}

	if json.NewEncoder(stdout).Encode([]scout.Profile{scout.Standard, scout.Review, scout.Custom}) != nil {
		return 2
	}

	return 0
}
