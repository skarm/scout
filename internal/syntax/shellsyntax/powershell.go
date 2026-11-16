package shellsyntax

import "strings"

func IsPowerShell(name string) bool {
	switch strings.ToLower(name) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
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
		case "-nologo", "-noprofile", "-noninteractive", "-noexit", "-sta", "-mta":
		case "-executionpolicy", "-inputformat", "-outputformat", "-windowstyle":
			i++
			if i >= length {
				return -1
			}

			value, known := argument(i)
			if !known || value == "" || strings.HasPrefix(value, "-") {
				return -1
			}
		case "-command":
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
