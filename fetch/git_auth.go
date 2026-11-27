package fetch

import (
	"net/url"
	"strings"
)

// GitCredentials is an immutable Basic credential for one HTTPS Git origin.
// The token is sent only by Scout's checked HTTP transport.
type GitCredentials struct {
	host, port  string
	user, token string
}

// NewGitCredentials associates an explicit user and token with one HTTPS
// origin. An origin is a scheme, host and optional port.
func NewGitCredentials(origin, user, token string) (*GitCredentials, error) {
	address, err := parseURL(origin, true)
	if err != nil || address.Scheme != "https" || address.Path != "" && address.Path != "/" {
		return nil, fail("invalid_git_auth_origin")
	}

	if !gitCredentialText(user, 256) || strings.Contains(user, ":") || !gitCredentialText(token, 4096) {
		return nil, fail("invalid_git_credentials")
	}

	return &GitCredentials{host: address.Hostname(), port: gitHTTPSPort(address), user: user, token: token}, nil
}

func gitCredentialText(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsFunc(value, func(r rune) bool {
		return r < '!' || r > '~'
	})
}

func (c *GitCredentials) applies(target *url.URL) bool {
	return c != nil && target.Scheme == "https" && strings.EqualFold(target.Hostname(), c.host) && gitHTTPSPort(target) == c.port
}

func gitHTTPSPort(target *url.URL) string {
	if port := target.Port(); port != "" {
		return port
	}

	return "443"
}

// IsGitCloneURL identifies unambiguous top-level Git targets. The caller still
// needs to validate the URL and obtain network permission before acquisition.
func IsGitCloneURL(raw string) bool {
	address, err := url.Parse(raw)
	if err != nil || address.Hostname() == "" {
		return false
	}

	if strings.EqualFold(address.Hostname(), "github.com") {
		_, _, err := githubRepository(address)
		return err == nil
	}

	return strings.HasSuffix(strings.TrimRight(address.Path, "/"), ".git")
}
