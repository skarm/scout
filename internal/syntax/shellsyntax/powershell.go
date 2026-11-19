package shellsyntax

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
)

const (
	powerShellNoLogoOption          = "-nologo"
	powerShellNoProfileOption       = "-noprofile"
	powerShellNonInteractiveOption  = "-noninteractive"
	powerShellNoExitOption          = "-noexit"
	powerShellSTAOption             = "-sta"
	powerShellMTAOption             = "-mta"
	powerShellExecutionPolicyOption = "-executionpolicy"
	powerShellInputFormatOption     = "-inputformat"
	powerShellOutputFormatOption    = "-outputformat"
	powerShellWindowStyleOption     = "-windowstyle"
	powerShellCommandOption         = "-command"
)

func IsPowerShell(name string) bool {
	switch strings.ToLower(name) {
	case language.ExecutablePowerShell, language.ExecutablePowerShellExe, language.ExecutablePowerShellCore, language.ExecutablePowerShellCoreExe:
		return true
	default:
		return false
	}
}

// PowerShellCommandIndex recognizes the explicit command-text option after
// supported startup switches. File operands and stdin are separate modes.
func PowerShellCommandIndex(length int, argument func(int) (string, bool)) int {
	for i := 0; i < length; i++ {
		option, known := argument(i)
		if !known {
			return -1
		}

		switch strings.ToLower(option) {
		case powerShellNoLogoOption, powerShellNoProfileOption, powerShellNonInteractiveOption, powerShellNoExitOption, powerShellSTAOption, powerShellMTAOption:
		case powerShellExecutionPolicyOption, powerShellInputFormatOption, powerShellOutputFormatOption, powerShellWindowStyleOption:
			i++
			if i >= length {
				return -1
			}

			value, known := argument(i)
			if !known || value == "" || strings.HasPrefix(value, "-") {
				return -1
			}
		case powerShellCommandOption:
			if i+1 < length {
				value, known := argument(i + 1)
				if !known || value != "-" && value != "" {
					return i + 1
				}
			}

			return -1
		default:
			return -1
		}
	}

	return -1
}
