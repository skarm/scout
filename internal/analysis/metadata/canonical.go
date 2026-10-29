package metadata

import (
	"encoding/json"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

// Discard token positions but retain values and types, including numbers.
// Parser depth/node budgets bound this traversal. Object member order is not
// a semantic parameter change; array order remains meaningful by default.
func canonicalHash(n *jsonconfig.Node) string {
	if n == nil {
		return artifact.Hash([]byte("absent"))
	}

	members := map[string]string{}
	for _, m := range n.Members {
		members[m.Key] = canonicalHash(m.Value)
	}

	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	items := make([]string, 0)
	for _, key := range keys {
		items = append(items, key, members[key])
	}

	for _, x := range n.Elements {
		items = append(items, canonicalHash(x))
	}

	value := canonicalNumber(n.Kind, n.String)

	b, _ := json.Marshal([]any{n.Kind, value, n.Bool, items})

	return artifact.Hash(b)
}

func canonicalNumber(kind, value string) string {
	if kind == "number" && len(value) <= 256 {
		bounded := true

		if at := strings.IndexAny(value, "eE"); at >= 0 {
			exponent, e := strconv.ParseInt(value[at+1:], 10, 32)
			bounded = e == nil && exponent >= -4096 && exponent <= 4096
		}

		if bounded {
			if number, ok := new(big.Rat).SetString(value); ok {
				value = number.RatString()
			}
		}
	}

	return value
}
