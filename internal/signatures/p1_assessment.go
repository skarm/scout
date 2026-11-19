package signatures

import "github.com/skarm/scout/report"

const (
	ransomwareRule               = "ransomware_behavior"
	contextPaymentPattern        = "$context_then_payment"
	multilineShellRule           = "reverse_shell_multiline"
	c2FrameworkRule              = "c2_framework_indicators"
	reverseShellRule             = "reverse_shell"
	networkReconRule             = "network_reconnaissance"
	phishingKitRule              = "phishing_kit"
	backdoorPersistenceRule      = "backdoor_persistence"
	keyloggerRule                = "keylogger_indicators"
	infoStealerRule              = "info_stealer"
	offensiveToolsRule           = "offensive_tool_references"
	privilegeEscalationRule      = "privilege_escalation_tools"
	exploitFrameworkRule         = "exploit_framework"
	cryptoStratumRule            = "crypto_stratum_protocol"
	cryptoMiningPoolsRule        = "crypto_mining_pools"
	cryptoMinerRule              = "crypto_miner_software"
	cryptoCoinjackingRule        = "crypto_coinjacking"
	paymentThenContextPattern    = "$payment_then_context"
	explicitRansomPaymentPattern = "$explicit_ransom_payment"
)

func p1BaseSeverity(rule string) report.Severity {
	switch rule {
	case reverseShellRule, multilineShellRule:
		return report.High
	case networkReconRule, phishingKitRule:
		return report.Medium
	case backdoorPersistenceRule, keyloggerRule, ransomwareRule,
		c2FrameworkRule, infoStealerRule, offensiveToolsRule,
		privilegeEscalationRule, exploitFrameworkRule, cryptoStratumRule,
		cryptoMiningPoolsRule, cryptoMinerRule, cryptoCoinjackingRule:
		return report.Low
	default:
		return ""
	}
}

func p1Description(match Match) string {
	var subject string

	switch match.Rule {
	case reverseShellRule, multilineShellRule:
		return "Socket, shell or stream-redirection chain signature; execution is unverified"
	case backdoorPersistenceRule:
		subject = "Persistence"
	case keyloggerRule:
		subject = "Keyboard capture"
	case ransomwareRule:
		subject = "Encryption, overwrite or ransom"
	case c2FrameworkRule:
		subject = "C2 framework"
	case infoStealerRule:
		subject = "Sensitive artifact or credential dumping"
	case offensiveToolsRule, networkReconRule, privilegeEscalationRule, exploitFrameworkRule:
		subject = "Security tool or exploit"
	case phishingKitRule:
		subject = "Credential collection"
	case cryptoStratumRule, cryptoMiningPoolsRule, cryptoMinerRule, cryptoCoinjackingRule:
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
