// Package literals classifies literal values without resolving or executing code.
package literals

import (
	"path"
	"strings"
)

const MaxStaticStringBytes = 4096

func IsShell(s string) bool {
	switch path.Base(strings.ReplaceAll(s, "\\", "/")) {
	case "sh", "bash", "dash", "zsh", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	}

	return false
}

func SensitivePath(s string) bool {
	s = path.Clean(s)
	if s == "/etc/shadow" {
		return true
	}

	for _, tail := range []string{".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials"} {
		if s == tail || strings.HasSuffix(s, "/"+tail) {
			return true
		}
	}

	return false
}

func SensitiveName(s string) bool {
	s = strings.ToUpper(s)
	for _, token := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY"} {
		if s == token || strings.HasSuffix(s, "_"+token) || strings.HasPrefix(s, token+"_") || strings.Contains(s, "_"+token+"_") {
			return true
		}
	}

	return false
}
