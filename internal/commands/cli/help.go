package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/scout/mcp"
)

const operatorHelp = `
doctor (alias: selftest):
  --format text|json         Output format (default: terminal; alias for text).
  --timeout DURATION         Total self-test deadline (default: 90s; maximum: 2m).

config validate:
  Uses scan configuration, policy, checks, service and budget flags.
  --config FILE              Explicit operator configuration; omitted uses defaults.
  Prints the prepared inspection plan as JSON. No targets or report outputs.

baseline create / baseline approve:
  --from FILE                Required report JSON for create; baseline JSON for approve.
  --output FILE              Required destination outside the source file.
  --reason TEXT              Required operator justification for nonempty baselines.
  --expires RFC3339          Required future expiry time.
  create writes pending entries; approve approves every entry in the selected file.

rules list (also: rules):
  --all                      Include adapted, Python and YARA rules (default: false).

profiles / capabilities / version:
  No command flags. Print profile names, compiled backends or the build version.
  --version is also accepted at the root.

knowledge:
  --mode MODE                Print a trusted runtime prompt instead of catalog JSON.
                             discovery, intent, tool_consistency, assessment,
                             proposal_assessment or quality (default: unset).

integrations list (also: integrations):
  No flags. List compiled reviewer bundles.

integrations export:
  --bundle NAME              Required: agent-skill, claude-code, codex, pi,
                             opencode or review-materials.
  --output FILE              Required new ZIP destination; never replaces a file.

registry fetch:
  --endpoint URL             Registry endpoint (default:
                             https://registry.modelcontextprotocol.io/v0/servers).
  --name NAME                Exact server name (default: all names).
  --latest                   Select registry-asserted latest records (default: false).
  --allow-download           Authorize registry requests (default: false).
  --allow-loopback           Permit a numeric loopback endpoint (default: false).
  --max-pages N              Maximum pages (default: 32).
  --max-bytes N              Aggregate response bytes (default: 8388608).
  --output FILE              Snapshot JSON destination (default: stdout).

registry compare:
  Takes two positional snapshot paths: <previous> <current>.
  --output FILE              Comparison JSON destination (default: stdout).

attestation verify:
  --public-key FILE          Required trusted PKIX public key PEM outside inputs.
  --envelope FILE            Required DSSE envelope or OMS bundle.
  --artifact FILE            Required artifact whose exact bytes are verified.
  --subject NAME             Required exact signed subject name.

Syntax and defaults:
  Put flags before positional inputs; -- ends flag parsing.
  Boolean flags without a value enable the option; use --flag=false to disable it.
  Byte limits are integer bytes; durations use units such as 500ms, 30s or 2m.
  Explicit flags override --config; shown defaults apply without configuration.
  Configuration, baseline, extra rules and caches must be outside inspected inputs.
  Repeat --report, --external-origin, --target or --origin for multiple values.
  scan accepts 1..32 targets, or one --input - with --name and no positional inputs.
  Profile aliases: basic = builtins-only custom, extended = standard, semantic = review.
  Format alias: terminal = text. --checks replaces the optional check selection.
  A subset or none requires --profile custom; built-in checks always remain enabled.

Full manual: docs/reference/cli.md (English), docs/reference/cli.ru.md (Russian).
`

func fullHelp(stdout io.Writer) int {
	var text strings.Builder
	text.WriteString(usage)
	text.WriteString("\nScan flags (batch is an alias; defaults apply without --config):\n")

	_, scan := requestFlagSet("scan", io.Discard, nil)

	for _, group := range []string{"Input and configuration", "Reports", "Policy", "Checks", "Concurrency and budgets", "Downloads", "External references", "Vulnerabilities", "LLM review"} {
		_, _ = fmt.Fprintf(&text, "\n%s:\n", group)

		scan.VisitAll(func(f *flag.Flag) {
			if scanFlagGroup(f.Name) == group {
				appendFlagHelp(&text, f)
			}
		})
	}

	text.WriteString("\ncompare:\n  Uses scan flags except --input, --name and download/external controls.\n")

	_, comparison := requestFlagSet("compare", io.Discard, nil)
	appendFlagHelp(&text, comparison.Lookup("max-changes"))
	text.WriteString("  Both inputs must be local; --max-changes accepts 1..20000.\n")
	text.WriteString("\nmcp:\n  Uses scan configuration, policy, checks, service and budget flags.\n  Inputs use --target or tool uploads; reports are returned through MCP.\n")

	invocation := mcpInvocation{options: mcp.DefaultOptions(), transport: "stdio", listen: "127.0.0.1:8837"}
	transport := flag.NewFlagSet("mcp", flag.ContinueOnError)
	invocation.bind(transport)
	transport.VisitAll(func(f *flag.Flag) { appendFlagHelp(&text, f) })
	text.WriteString(operatorHelp)

	return writeText(stdout, text.String())
}

func scanFlagGroup(name string) string {
	switch name {
	case "format", "output", "report":
		return "Reports"
	case "baseline", "allow-baseline-globs", "fail-on", "block-at", "scope":
		return "Policy"
	case "checks", "yara-rules":
		return "Checks"
	case "allow-download", "revision":
		return "Downloads"
	case "follow-external":
		return "External references"
	case "vuln", "allow-vulnerability-network":
		return "Vulnerabilities"
	case "semantic", "quality-review", "allow-source-upload":
		return "LLM review"
	case "workers", "target-workers", "timeout", "parser-timeout":
		return "Concurrency and budgets"
	}

	for prefix, group := range map[string]string{
		"download-": "Downloads", "external-": "External references",
		"osv-": "Vulnerabilities", "llm-": "LLM review",
		"max-": "Concurrency and budgets", "extract-": "Concurrency and budgets",
	} {
		if strings.HasPrefix(name, prefix) {
			return group
		}
	}

	return "Input and configuration"
}

func appendFlagHelp(text *strings.Builder, f *flag.Flag) {
	value, description := flag.UnquoteUsage(f)
	argument := "--" + f.Name

	if boolean, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
		argument += "[=BOOL]"
	} else if value != "" {
		argument += " " + strings.ToUpper(value)
	}

	defaultValue := f.DefValue
	if f.Name == "scope" && defaultValue == "" {
		defaultValue = "conservative"
	}

	if defaultValue == "" {
		defaultValue = "unset"
	}

	_, _ = fmt.Fprintf(text, "  %s\n      %s (default: %s)\n", argument, description, defaultValue)
}
