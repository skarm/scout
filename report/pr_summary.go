package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const maxPRSummaryChanges = 100

// PRSummary identifies the project, revision and directory for candidate source links.
type PRSummary struct {
	project                     url.URL
	blobPath, commit, directory string
}

// NewPRSummary validates operator-supplied GitHub source link coordinates.
func NewPRSummary(head, directory string) (PRSummary, error) {
	name, commit, _ := strings.Cut(head, "@")
	owner, repository, _ := strings.Cut(name, "/")

	if !validPROwner(owner) || !validPRRepository(repository) || !validPRCommit(commit) {
		return PRSummary{}, errors.New("--pr-head requires a GitHub OWNER/REPO@SHA with a full lowercase commit SHA")
	}

	project := url.URL{Scheme: "https", Host: "github.com", Path: "/" + owner + "/" + repository}

	return newPRSummary(project, "/blob/", commit, directory)
}

// NewGitLabPRSummary builds source links from an absolute GitLab project URL and commit.
func NewGitLabPRSummary(head, directory string) (PRSummary, error) {
	name, commit, _ := strings.Cut(head, "@")

	project, err := url.Parse(name)
	if err != nil || !validPRCommit(commit) || !validGitLabProject(project, name) {
		return PRSummary{}, errors.New("--pr-head requires a GitLab HTTP(S) project URL followed by @ and a full lowercase commit SHA")
	}

	return newPRSummary(*project, "/-/blob/", commit, directory)
}

func validGitLabProject(project *url.URL, name string) bool {
	if (project.Scheme != "http" && project.Scheme != "https") || project.Hostname() == "" ||
		project.User != nil || project.RawPath != "" || strings.ContainsAny(name, "?#") {
		return false
	}

	projectPath := strings.TrimPrefix(project.Path, "/")
	if !strings.ContainsRune(projectPath, '/') {
		return false
	}

	for segment := range strings.SplitSeq(projectPath, "/") {
		if segment == "-" || !validPRRepository(segment) {
			return false
		}
	}

	return true
}

func newPRSummary(project url.URL, blobPath, commit, directory string) (PRSummary, error) {
	if directory != "" && !validComparisonSourcePath(directory) {
		return PRSummary{}, errors.New("--pr-path requires a repository-relative POSIX directory")
	}

	return PRSummary{project: project, blobPath: blobPath, commit: commit, directory: directory}, nil
}

func validPRCommit(commit string) bool {
	return len(commit) == 40 && !strings.ContainsFunc(commit, func(c rune) bool {
		return (c < '0' || c > '9') && (c < 'a' || c > 'f')
	})
}

func validPROwner(owner string) bool {
	return owner != "" && owner[0] != '-' && !strings.ContainsFunc(owner, func(c rune) bool {
		return !asciiAlphanumeric(c) && c != '-'
	})
}

func validPRRepository(repository string) bool {
	return repository != "" && repository != "." && repository != ".." && !strings.ContainsFunc(repository, func(c rune) bool {
		return !asciiAlphanumeric(c) && c != '-' && c != '_' && c != '.'
	})
}

func asciiAlphanumeric(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// WritePRSummary renders a compact, commit-linked Markdown summary of a comparison.
func (p PreparedDocument) WritePRSummary(w io.Writer, summary PRSummary) error {
	if w == nil || !p.Valid() || !p.ValidComparisonRoles() || p.document.Run.Comparison == nil ||
		p.document.Run.Comparison.Capabilities == nil || summary.commit == "" {
		return errors.New("PR summary requires a prepared capability comparison and a source revision")
	}

	var out bytes.Buffer

	document := p.document
	candidate := document.Run.Targets[1].Analysis
	capabilities := document.Run.Comparison.Capabilities

	out.WriteString("## Scout package review\n\n")

	_, _ = fmt.Fprintf(&out, "Decision **%s** · Inspection **%s** · Candidate findings **%d**\n\n",
		document.Evaluation.Decision, document.Run.State, len(candidate.Findings))
	if digest := candidate.Artifact.SnapshotSHA256; digest != "" {
		_, _ = fmt.Fprintf(&out, "Candidate package SHA-256 %s\n\n", mdCode(digest))
	}

	for _, reason := range document.Evaluation.Reasons {
		_, _ = fmt.Fprintf(&out, "- %s.\n", decisionReason(reason))
	}

	out.WriteString("\n### New static capabilities\n\n")

	if document.Run.State != RunComplete {
		out.WriteString("Inspection is incomplete. The list may omit capabilities.\n\n")
	}

	shown := min(len(capabilities.Changes), maxPRSummaryChanges)
	for _, change := range capabilities.Changes[:shown] {
		_, _ = fmt.Fprintf(&out, "- %s", prCapabilityLabel(change.Kind))
		if change.Destination != "" {
			_, _ = fmt.Fprintf(&out, " to %s", mdCode(change.Destination))
		}

		if change.Status == "unverified" {
			out.WriteString(" (previous version unverified)")
		}

		location := fmt.Sprintf("%s:%d", change.Source.Path, change.Line)
		_, _ = fmt.Fprintf(&out, " at %s ([view line](<%s>))\n", mdCode(location), summary.sourceLink(change.Source.Path, change.Line))
	}

	if shown == 0 {
		out.WriteString("No new capabilities were observed within the selected coverage.\n")
	}

	if unshown := len(capabilities.Changes) - shown; unshown > 0 {
		_, _ = fmt.Fprintf(&out, "\n%d more retained capability changes are available in the JSON report.\n", unshown)
	}

	if capabilities.Omitted > 0 {
		_, _ = fmt.Fprintf(&out, "\n%d capability changes exceeded the comparison limit.\n", capabilities.Omitted)
	}

	out.WriteString("\nStatic observations do not establish execution or effective agent permissions.\n")

	return writeDocumentBytes(w, out.Bytes())
}

func (s PRSummary) sourceLink(name string, line int) string {
	if s.directory != "" {
		name = s.directory + "/" + name
	}

	loc := s.project
	loc.Path += s.blobPath + s.commit + "/" + name
	loc.Fragment = "L" + strconv.Itoa(line)

	return loc.String()
}

func prCapabilityLabel(kind string) string {
	switch kind {
	case CapabilityNetwork:
		return "Network operation"
	case CapabilityDNS:
		return "DNS query"
	case "sensitive_read":
		return "Sensitive data read"
	case "untrusted_input":
		return "External input"
	case "command_execution":
		return "Command execution"
	case "file_write":
		return "File mutation"
	case "infrastructure_mutation":
		return "Infrastructure mutation"
	case "allowed-tools":
		return "Allowed tools declaration"
	case "permissions":
		return "Permission declaration"
	case EnvironmentMCPIdentifier:
		return "MCP server declaration"
	case EnvironmentToolIdentifier:
		return "Tool declaration"
	default:
		return "Capability"
	}
}
