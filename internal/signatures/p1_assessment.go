package signatures

import "github.com/skarm/scout/report"

const (
	ransomwareRule        = "ransomware_behavior"
	contextPaymentPattern = "$context_then_payment"
	multilineShellRule    = "reverse_shell_multiline"
	c2FrameworkRule       = "c2_framework_indicators"
)

func p1BaseSeverity(rule string) report.Severity {
	switch rule {
	case "reverse_shell", multilineShellRule:
		return report.High
	case "network_reconnaissance", "phishing_kit":
		return report.Medium
	case "backdoor_persistence", "keylogger_indicators", ransomwareRule,
		c2FrameworkRule, "info_stealer", "offensive_tool_references",
		"privilege_escalation_tools", "exploit_framework", "crypto_stratum_protocol",
		"crypto_mining_pools", "crypto_miner_software", "crypto_coinjacking":
		return report.Low
	default:
		return ""
	}
}

func p1Description(match Match) string {
	var subject string

	switch match.Rule {
	case "reverse_shell", multilineShellRule:
		return "Socket, shell or stream-redirection chain signature; execution is unverified"
	case "backdoor_persistence":
		subject = "Persistence"
	case "keylogger_indicators":
		subject = "Keyboard capture"
	case ransomwareRule:
		subject = "Encryption, overwrite or ransom"
	case c2FrameworkRule:
		subject = "C2 framework"
	case "info_stealer":
		subject = "Sensitive artifact or credential dumping"
	case "offensive_tool_references", "network_reconnaissance", "privilege_escalation_tools", "exploit_framework":
		subject = "Security tool or exploit"
	case "phishing_kit":
		subject = "Credential collection"
	case "crypto_stratum_protocol", "crypto_mining_pools", "crypto_miner_software", "crypto_coinjacking":
		subject = "Cryptocurrency mining"
	default:
		return ""
	}

	switch match.Severity {
	case report.High:
		return subject + " action signature; intent and authorization are unverified"
	case report.Medium:
		return subject + " use or behavior indicators; intent is unverified"
	default:
		return subject + " reference or capability indicator; harmful behavior is unverified"
	}
}

func validBuiltinSeverity(match Match) bool {
	if match.Severity == builtinSeverity(match.Rule, false) || match.Severity == builtinSeverity(match.Rule, true) {
		return true
	}

	return match.Severity == report.Medium && p1BaseSeverity(match.Rule) == report.Low
}
