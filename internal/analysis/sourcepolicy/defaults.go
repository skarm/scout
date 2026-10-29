// Package sourcepolicy recognizes literal default package sources without network access.
package sourcepolicy

import (
	"net/url"
	"strings"

	"github.com/skarm/scout/report"
)

func Default(s, eco string) bool {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}

	if eco == report.EcosystemNPM {
		return u.Host == "registry.npmjs.org"
	}

	return u.Host == "pypi.org" || u.Host == "files.pythonhosted.org"
}

// ShellDefault also recognizes Cargo's literal registry declarations.
func ShellDefault(value, kind string) bool {
	if kind == "cargo" {
		v := strings.TrimRight(value, "/")
		return v == "sparse+https://index.crates.io" || v == "https://github.com/rust-lang/crates.io-index"
	}

	return Default(value, kind)
}
