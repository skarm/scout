package shell

import "strings"

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var curlOptionKinds = map[string]curlOptionKind{
	"--silent":          curlFlag,
	"--show-error":      curlFlag,
	"--fail":            curlFlag,
	"--location":        curlFlag,
	"--insecure":        curlFlag,
	"--compressed":      curlFlag,
	"--globoff":         curlFlag,
	"--no-buffer":       curlFlag,
	"--disable":         curlFlag,
	"--remote-name":     curlDiscardOutput,
	"--remote-name-all": curlDiscardOutput,
	"--head":            curlDiscardOutput,
	"--out-null":        curlDiscardOutput,
	"-d":                curlDataFile,
	"--data":            curlDataFile,
	"--data-ascii":      curlDataFile,
	"--data-binary":     curlDataFile,
	"--json":            curlDataFile,
	"--data-urlencode":  curlDataFile,
	"-T":                curlUploadFile,
	"--upload-file":     curlUploadFile,
	"--data-raw":        curlDataLiteral,
	"-H":                curlDataLiteral,
	"--header":          curlDataLiteral,
	"-u":                curlDataLiteral,
	"--user":            curlDataLiteral,
	"-o":                curlOutput,
	"--output":          curlOutput,
	"--url":             curlURL,
	"-A":                curlIgnoreValue,
	"--user-agent":      curlIgnoreValue,
	"-X":                curlIgnoreValue,
	"--request":         curlIgnoreValue,
	"--connect-timeout": curlIgnoreValue,
	"--max-time":        curlIgnoreValue,
	"--retry":           curlIgnoreValue,
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var curlBodyKinds = map[curlOptionKind]struct{ file, at bool }{
	curlDataFile:    {at: true},
	curlUploadFile:  {file: true},
	curlDataLiteral: {},
}

type shellBody struct {
	value    shellValue
	file, at bool
}
type curlRequest struct {
	valid, remote, stdout bool
	bodies                []shellBody
	outputs               []shellValue
	urls                  int
	destinations          []shellValue
}

type curlOptionKind uint8

const (
	curlFlag curlOptionKind = iota + 1
	curlDiscardOutput
	curlIgnoreValue
	curlOutput
	curlURL
	curlDataFile
	curlUploadFile
	curlDataLiteral
)

// This is a finite option model, not execution or a complete curl CLI parser.
// Unknown options invalidate the model rather than shifting argument positions.
func curlArguments(args []shellValue) curlRequest {
	r := curlRequest{valid: true, stdout: true}
	options := true

	for i := 0; i < len(args); i++ {
		next, more := r.consumeArgument(args, i, &options)
		if !more {
			break
		}

		i = next
	}

	return r
}

func curlOperand(value string, options bool) bool {
	return !options || !strings.HasPrefix(value, "-") || value == "-"
}

func (r *curlRequest) consumeArgument(args []shellValue, i int, options *bool) (int, bool) {
	v := args[i]
	if !v.known {
		r.valid = false
		return i, true
	}

	s := v.text
	if *options && s == "--" {
		*options = false
		return i, true
	}

	if curlOperand(s, *options) {
		r.remote = r.remote || httpURL(s)
		r.urls++
		r.destinations = append(r.destinations, v)

		return i, true
	}

	key, value, attached := r.option(v)
	if key == "" {
		return i, true
	}

	if !r.valueOption(key, attached) {
		return i, true
	}

	if !attached {
		i++
		if i >= len(args) {
			r.valid = false
			return i, false
		}

		value = args[i]
	}

	r.applyOption(key, value)

	return i, true
}

func (r *curlRequest) option(v shellValue) (string, shellValue, bool) {
	if !strings.HasPrefix(v.text, "--") {
		return r.shortOption(v)
	}

	if key, text, attached := strings.Cut(v.text, "="); attached {
		value := v
		value.text = text

		return key, value, true
	}

	return v.text, shellValue{}, false
}

func (r *curlRequest) shortOption(v shellValue) (key string, value shellValue, attached bool) {
	flags := v.text[1:]
	for j := 0; j < len(flags); j++ {
		c := flags[j]
		if strings.ContainsRune("doTHuAX", rune(c)) {
			key = "-" + string(c)

			if j+1 < len(flags) {
				value = v
				value.text = flags[j+1:]
				attached = true
			}

			break
		}

		if strings.ContainsRune("OI", rune(c)) {
			r.stdout = false
		} else if !strings.ContainsRune("fsSLkigNq012346", rune(c)) {
			r.valid = false
		}
	}

	return key, value, attached
}

func (r *curlRequest) valueOption(key string, attached bool) bool {
	kind, known := curlOptionKinds[key]
	if !known {
		r.valid = false
		return false
	}

	switch kind {
	case curlDiscardOutput:
		r.stdout = false
		fallthrough
	case curlFlag:
		if attached {
			r.valid = false
		}

		return false
	default:
		return true
	}
}

func (r *curlRequest) applyOption(key string, value shellValue) {
	kind := curlOptionKinds[key]
	switch kind {
	case curlOutput:
		r.outputs = append(r.outputs, value)
		if !value.known || value.text != "-" {
			r.stdout = false
		}
	case curlURL:
		r.urls++

		r.destinations = append(r.destinations, value)
		if value.known {
			r.remote = r.remote || httpURL(value.text)
		}
	default:
		if mode, body := curlBodyKinds[kind]; body {
			r.bodies = append(r.bodies, curlBodyValue(value, mode.file, mode.at))
		}
	}
}

func curlBodyValue(value shellValue, file, at bool) shellBody {
	if at {
		file = value.known && strings.HasPrefix(value.text, "@")
	}

	return shellBody{value: value, file: file, at: at}
}

func httpURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var wgetOptionKinds = map[string]wgetOptionKind{
	"-O":                     wgetOutput,
	"--output-document":      wgetOutput,
	"--quiet":                wgetSkip,
	"--no-check-certificate": wgetSkip,
}

type wgetOptionKind uint8

const (
	wgetOperand wgetOptionKind = iota
	wgetInvalid
	wgetOutput
	wgetInlineOutput
	wgetSkip
	wgetShort
)

type wgetRequest struct{ stdout, remote bool }

func wgetStdout(args []shellValue) bool {
	request := wgetRequest{}
	for i := 0; i < len(args); i++ {
		next, valid := request.argument(args, i)
		if !valid {
			return false
		}

		i = next
	}

	return request.stdout && request.remote
}

func wgetOption(v shellValue) wgetOptionKind {
	if !v.known {
		return wgetInvalid
	}

	value := v.text
	if kind, known := wgetOptionKinds[value]; known {
		return kind
	}

	if strings.HasPrefix(value, "--output-document=") {
		return wgetInlineOutput
	}

	if strings.HasPrefix(value, "--") {
		return wgetInvalid
	}

	if strings.HasPrefix(value, "-") {
		return wgetShort
	}

	return wgetOperand
}

func (r *wgetRequest) argument(args []shellValue, i int) (int, bool) {
	value := args[i]
	switch wgetOption(value) {
	case wgetOutput:
		operand, valid := knownShellOperand(args, i+1)
		if !valid {
			return i + 1, false
		}

		r.stdout = operand.text == "-"

		return i + 1, true
	case wgetInlineOutput:
		r.stdout = strings.TrimPrefix(value.text, "--output-document=") == "-"
	case wgetSkip:
	case wgetShort:
		stdout, next, valid := wgetShortOptions(value.text[1:], args, i, r.stdout)
		r.stdout = stdout

		return next, valid
	case wgetInvalid:
		return i, false
	default:
		r.remote = r.remote || httpURL(value.text)
	}

	return i, true
}

func wgetShortOptions(flags string, args []shellValue, i int, stdout bool) (bool, int, bool) {
	for j := 0; j < len(flags); j++ {
		if flags[j] == 'O' {
			if j+1 < len(flags) {
				stdout = flags[j+1:] == "-"
			} else {
				i++

				operand, valid := knownShellOperand(args, i)
				if !valid {
					return false, i, false
				}

				stdout = operand.text == "-"
			}

			break
		}

		if !strings.ContainsRune("qnv", rune(flags[j])) {
			return false, i, false
		}
	}

	return stdout, i, true
}
