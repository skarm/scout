package shell

import (
	"errors"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

// A finite single-query CLI grammar. Batch, reverse and unknown options leave
// an explicit gap instead of reinterpreting an option's value as the query.
func dnsArguments(command string, args []shellValue) (shellValue, bool) {
	r := dnsRequest{command: command}

	for i := 0; i < len(args); i++ {
		next, valid := r.argument(args, i)
		if !valid {
			return shellValue{}, false
		}

		i = next
	}

	return r.query, r.found
}

type dnsRequest struct {
	command               string
	query                 shellValue
	found, server, record bool
}

func (r *dnsRequest) argument(args []shellValue, i int) (int, bool) {
	v := args[i]
	if !v.known {
		if v.prefix == '-' || v.prefix == '+' || r.command == "dig" && v.prefix == '@' {
			return i, false
		}

		return i, r.operand(v)
	}

	if dnsFlag(r.command, v.text) || dnsInlineOption(r.command, v.text) {
		return i, true
	}

	if r.command == "dig" && strings.HasPrefix(v.text, "@") {
		valid := !r.server && len(v.text) > 1
		r.server = true

		return i, valid
	}

	if dnsValueOption(r.command, v.text) {
		return i + 1, r.optionValue(v.text, args, i+1)
	}

	if strings.HasPrefix(v.text, "-") || strings.HasPrefix(v.text, "+") {
		return i, false
	}

	if r.command == "dig" && dnsRecord(v.text) {
		valid := !r.record
		r.record = true

		return i, valid
	}

	return i, r.operand(v)
}

func (r *dnsRequest) operand(v shellValue) bool {
	if !r.found {
		r.query, r.found = v, true
		return true
	}

	if r.command != "dig" && !r.server && v.known {
		r.server = true
		return true
	}

	return false
}

func (r *dnsRequest) optionValue(option string, args []shellValue, i int) bool {
	if i >= len(args) {
		return false
	}

	if option == "-q" {
		if r.found {
			return false
		}

		r.query, r.found = args[i], true

		return true
	}

	return args[i].known
}

func dnsValueOption(command, value string) bool {
	return command != "nslookup" && (value == "-t" || value == "-c" || command == "dig" && (value == "-q" || value == "-p"))
}

func dnsInlineOption(command, value string) bool {
	return command == "nslookup" && (strings.HasPrefix(value, "-type=") || strings.HasPrefix(value, "-query=") || strings.HasPrefix(value, "-q=") || strings.HasPrefix(value, "-class="))
}

func dnsFlag(command, value string) bool {
	switch command {
	case "dig":
		switch value {
		case "+short", "+noall", "+answer", "+tcp", "+notcp", "+trace", "+recurse", "+norecurse", "+search", "+nosearch", "-4", "-6", "-r":
			return true
		}
	case "host":
		switch value {
		case "-4", "-6", "-a", "-v", "-T", "-r":
			return true
		}
	}

	return false
}

func dnsRecord(value string) bool {
	switch strings.ToUpper(value) {
	case "A", "AAAA", "TXT", "MX", "NS", "CNAME", "SOA", "SRV", "PTR", "ANY", "CAA", "NAPTR", "TLSA":
		return true
	}

	return false
}

func (a *shellWalk) dnsCommand(c *shellsyntax.Command, name string, args []shellValue) {
	query, valid := dnsArguments(name, args)
	if !valid {
		a.gap = errors.New("shell DNS command arguments are unresolved")
		return
	}

	if !query.known {
		a.gap = errors.New("shell DNS query name is unresolved")
	}

	if a.observeDNS != nil {
		a.observeDNS(query.text, c.Span, query.credential)
	}
}
