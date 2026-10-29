// Package cli is the command adapter for the public scanner, policy and report APIs.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/report"
)

const usage = `Usage:
  scout scan [flags] -- <target> [target...]
  scout scan [flags] --input - --name <relative-name>
  scout compare [flags] -- <before> <after>
  scout rules list [--all]
  scout doctor [--format json|text]
  scout config validate --config <file>
  scout baseline create|approve [flags]
  scout mcp [flags]
  scout knowledge [flags]
  scout integrations [flags]
  scout registry fetch|compare [flags]
  scout verify-attestation --public-key KEY --envelope DSSE --artifact FILE --subject NAME
  scout version

Common flags: --config FILE --profile standard|review|custom --format text|json|sarif|markdown
  --report FORMAT=PATH (repeatable) --workers N --timeout DURATION --fail-on SEVERITY
  --baseline FILE --allow-download --allow-vulnerability-network --allow-source-upload
Network and source upload require separate explicit grants. Configuration is never discovered in targets.
Reports use scout.report/v1; stdout contains only the requested report, diagnostics go to stderr.
Exit: 0 complete/allow; 1 complete/review-or-block; 2 incomplete, invalid request or output failure.
`

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return 2
	}

	if len(args) == 0 {
		return usageError(stderr, "command required")
	}

	return inspectionCommand(ctx, args, stdout, stderr)
}

func inspectionCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	switch args[0] {
	case "scan", "batch":
		return scanCommand(ctx, args[1:], os.Stdin, stdout, stderr)
	case "compare":
		return compareCommand(ctx, args[1:], stdout, stderr)
	case "doctor", "selftest":
		return selftest(ctx, args[1:], stdout, stderr)
	case "mcp":
		return serveMCP(ctx, args[1:], os.Stdin, stdout, stderr)
	default:
		return operatorCommand(ctx, args, stdout, stderr)
	}
}

func operatorCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	switch args[0] {
	case "config":
		return configCommand(ctx, args[1:], stdout, stderr)
	case "baseline":
		return baselineCommand(ctx, args[1:], stderr)
	case "knowledge":
		return knowledgeCommand(args[1:], stdout, stderr)
	case "integrations":
		return integrationCommand(ctx, args[1:], stdout, stderr)
	case "profiles":
		return profilesCommand(args[1:], stdout, stderr)
	case "registry":
		return registryCommand(ctx, args[1:], stdout, stderr)
	case "verify-attestation":
		return attestationCommand(ctx, args[1:], stdout, stderr)
	default:
		return informationalCommand(args, stdout, stderr)
	}
}

func informationalCommand(args []string, stdout, stderr io.Writer) int {
	switch args[0] {
	case "help", "-h", "--help":
		return writeText(stdout, usage)
	case "version", "--version":
		if len(args) != 1 {
			return usageError(stderr, "version takes no arguments")
		}

		return writeText(stdout, scout.Version()+"\n")
	case "rules":
		return rulesCommand(args[1:], stdout, stderr)
	case "capabilities":
		if len(args) != 1 {
			return usageError(stderr, "capabilities takes no arguments")
		}

		if json.NewEncoder(stdout).Encode(struct {
			Version    string                    `json:"version"`
			Parsers    []report.ParserCapability `json:"parsers"`
			Signatures signatures.Capability     `json:"signatures"`
		}{Version: scout.Version(), Parsers: scout.ParserCapabilities(), Signatures: signatures.Backend()}) != nil {
			return 2
		}

		return 0
	default:
		return usageError(stderr, "unknown command")
	}
}

func rulesCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "list" {
		args = args[1:]
	}

	if len(args) > 1 || len(args) == 1 && args[0] != "--all" {
		return usageError(stderr, "rules list accepts --all")
	}

	if json.NewEncoder(stdout).Encode(scout.Rules(len(args) == 1)) != nil {
		return 2
	}

	return 0
}

func writeText(w io.Writer, text string) int {
	if _, err := io.WriteString(w, text); err != nil {
		return 2
	}

	return 0
}

func usageError(w io.Writer, message string) int {
	_, _ = fmt.Fprintln(w, message)
	_, _ = io.WriteString(w, usage)

	return 2
}
