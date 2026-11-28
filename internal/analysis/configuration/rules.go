// Package configuration checks captured agent, plugin and MCP declarations.
// These rules project static evidence from prepared documents.
package configuration

import "github.com/skarm/scout/internal/analysis/check"

// Rules returns the base configuration checks in catalog order.
func Rules() []check.Analyzer {
	return []check.Analyzer{
		agentConfigCheck{id: ruleAC001},
		agentConfigCheck{id: ruleAC002},
		agentConfigCheck{id: ruleAC003},
		agentConfigCheck{id: ruleSC001},
		agentConfigCheck{id: ruleMC001},
		agentConfigCheck{id: ruleMC002},
		agentConfigCheck{id: ruleMC003},
		agentConfigCheck{id: ruleMC004},
		bundledSurface{id: ruleBH1},
		bundledSurface{id: ruleBH2},
		bundledSurface{id: ruleBH3},
		bundledSurface{id: ruleBH4},
	}
}
