// Package literals classifies literal values without resolving or executing code.
package literals

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
)

const MaxStaticStringBytes = 4096

const (
	executableFish   = "fish"
	executableCMD    = "cmd"
	executableCMDExe = "cmd.exe"
)

func IsShell(s string) bool {
	switch path.Base(strings.ReplaceAll(s, "\\", "/")) {
	case language.ExecutableSh, language.ExecutableBash, language.ExecutableDash, language.ExecutableZsh, language.ExecutableKsh, executableFish, executableCMD, executableCMDExe, language.ExecutablePowerShell, language.ExecutablePowerShellExe, language.ExecutablePowerShellCore, language.ExecutablePowerShellCoreExe:
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
