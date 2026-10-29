package signatures

import "github.com/skarm/scout/report"

const (
	webhookRule         = "agent_skill_credential_exfiltration_webhook"
	remoteBootstrapRule = "agent_skill_remote_bootstrap_execution"
	metadataInstruction = "$param_injection"
)

// Description distinguishes an advisory from a strong signature without
// trusting a rule author's severity, confidence or description metadata.
func Description(match Match) string {
	if ciscoSeverity(match.Rule) != "" {
		return "Adapted Cisco compound signature; execution, authorization and data flow require structural verification"
	}

	switch match.Rule {
	case webhookRule:
		return "Sensitive-source and webhook-send indicators coexist; data flow is unverified"
	case remoteBootstrapRule:
		if match.Severity == report.High {
			return "Remote download and execution signature"
		}

		return "Remote installation or bootstrap-capable install hook indicator"
	case metadataPoisoningRule:
		if match.Severity == report.High {
			return "Instruction override or disclosure directive in metadata"
		}

		return "Encoded or hidden metadata content; instruction poisoning is unverified"
	default:
		return p1Description(match)
	}
}

// builtinSeverity is Scout policy. External metadata cannot set a finding's
// severity. Co-occurring sources and requests do not establish data flow.
func builtinSeverity(rule string, strong bool) report.Severity {
	if severity := ciscoSeverity(rule); severity != "" {
		return severity
	}

	switch rule {
	case webhookRule:
		return report.Medium
	case remoteBootstrapRule, metadataPoisoningRule:
		if strong {
			return report.High
		}

		return report.Low
	default:
		severity := p1BaseSeverity(rule)
		if strong && severity != "" {
			return report.High
		}

		return severity
	}
}

func ciscoSeverity(rule string) report.Severity {
	switch rule {
	case "Scout_Cisco_EncodedShell_DecodeExec", "Scout_Cisco_EncodedPowerShell_Exec":
		return report.High
	case "Scout_Cisco_CredentialRead_NetworkWrite", "Scout_Cisco_EncodedArchive_StageExec", "Scout_Cisco_RemoteMiner_AcquireExec", "Scout_Cisco_Cron_C2_Persistence", "Scout_Cisco_CodeExecution_Untrusted":
		return report.Medium
	case "Scout_Cisco_SQL_InjectionPayload":
		return report.Low
	}

	return ""
}
