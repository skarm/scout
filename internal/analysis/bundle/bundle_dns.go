package bundle

import (
	"errors"
	"net"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

// DNS names are data, never URLs. Do not pass them through URL authority parsing.
func canonicalDNSName(value string) string {
	if value == "." {
		return value
	}

	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if ip := net.ParseIP(name); ip != nil {
		return ip.String()
	}

	if name == "" || len(name) > 253 {
		return ""
	}

	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}

		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}

			return ""
		}
	}

	return name
}

func (b *bundleAnalysis) dnsEndpoint(file, value string, ref report.SourceRef) {
	b.surfaceFact("network", "", file, ref)

	host := canonicalDNSName(value)
	if host == "" {
		b.gap = errors.New("dynamic DNS query name is unresolved")
		return
	}

	if s := b.scope(file); s != nil {
		b.endpoints[s.file] = append(b.endpoints[s.file], bundleEndpoint{value: value, ref: ref})
		if !s.hosts[host] {
			b.emit(ruleNET001, ref, b.reference(s.file, 0, len(b.docs[s.file].Artifact().Content())))
		}
	}
}

func (b *bundleAnalysis) dnsFlow(ref, origin report.SourceRef, via []report.SourceRef) {
	refs := append([]report.SourceRef{origin}, via...)
	b.emit(ruleDNS001, ref, refs...)
	b.crossFlow(ref, origin, via)
}

// Each index is a component of the queried name, not an arbitrary API argument.
func bundleDNS(name, lang string) ([]int, string) {
	switch lang {
	case language.JavaScript, language.TypeScript:
		for _, prefix := range []string{"dns.", "dns.promises.", "dns/promises."} {
			method, ok := strings.CutPrefix(name, prefix)
			if !ok {
				continue
			}

			switch method {
			case "lookup", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr", "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTlsa", "resolveTxt":
				return []int{0}, ""
			}
		}
	case language.Python:
		switch name {
		case "socket.getaddrinfo":
			return []int{0}, "host"
		case "socket.gethostbyname", "socket.gethostbyname_ex":
			return []int{0}, ""
		}

		for _, prefix := range []string{"dns.resolver.", "dns.asyncresolver."} {
			if method, ok := strings.CutPrefix(name, prefix); ok {
				kind := resolverPython
				if prefix == "dns.asyncresolver." {
					kind = resolverPythonAsync
				}

				return resolverDNS(kind, method)
			}
		}
	case language.Go:
		switch name {
		case "net.LookupHost", "net.LookupIP", "net.LookupCNAME", "net.LookupMX", "net.LookupNS", "net.LookupTXT":
			return []int{0}, ""
		case "net.DefaultResolver.LookupHost", "net.DefaultResolver.LookupIPAddr", "net.DefaultResolver.LookupCNAME", "net.DefaultResolver.LookupMX", "net.DefaultResolver.LookupNS", "net.DefaultResolver.LookupTXT":
			return []int{1}, ""
		case "net.DefaultResolver.LookupIP", "net.DefaultResolver.LookupNetIP":
			return []int{2}, ""
		case "net.LookupSRV":
			return []int{0, 1, 2}, ""
		case "net.DefaultResolver.LookupSRV":
			return []int{1, 2, 3}, ""
		}
	}

	return nil, ""
}

func (b *bundleAnalysis) dnsCall(p *bundleProgram, n *bundleNode, callee bundleValue, args []bundleValue, ref report.SourceRef) bool {
	indices, keyword := bundleDNS(callee.name, p.language)
	if callee.resolver != nil {
		if callee.resolver.invalid || callee.resolver.kind == resolverNode && callee.resolverReceiver != n.children[0] {
			b.gap = errors.New("resolver method binding is unresolved")
			return true
		}

		indices, keyword = resolverDNS(callee.resolver.kind, callee.name)
		if len(indices) == 0 {
			if !resolverControl(callee.resolver.kind, callee.name) {
				b.gap = errors.New("resolver method is unresolved")
			}

			return true
		}
	}

	if len(indices) == 0 {
		return false
	}

	if n.kind == nodeConstruct {
		b.gap = errors.New("DNS API constructor invocation is unresolved")
		return true
	}

	if p.language == language.Python {
		index, valid := pythonDNSArgument(n.argumentNames, keyword)
		if !valid {
			b.gap = errors.New("DNS argument expansion or keyword is unresolved")
			return true
		}

		indices = []int{index}
	}

	values := make([]bundleValue, 0, len(indices))
	for _, i := range indices {
		if i >= len(args) || len(n.argumentNames) > i && n.argumentNames[i] != "" && n.argumentNames[i] != keyword {
			b.gap = errors.New("DNS query argument is unresolved")
			return true
		}

		values = append(values, args[i])
	}

	value := values[len(values)-1]
	if len(values) == 3 {
		value.known = value.known && values[0].known && values[1].known
		if value.known && (values[0].text != "" || values[1].text != "") {
			value.text = "_" + values[0].text + "._" + values[1].text + "." + value.text
		}
	}

	text := ""
	if value.known {
		text = value.text
	}

	b.dnsEndpoint(p.file, text, ref)

	for _, v := range values {
		if v.secret != nil {
			b.dnsFlow(ref, *v.secret, v.refs)
		}
	}

	return true
}

func pythonDNSArgument(names []string, keyword string) (int, bool) {
	index, found := 0, false

	for i, key := range names {
		if key == "*" || key != "" && keyword == "" {
			return 0, false
		}

		if keyword != "" && key == keyword {
			if found || names[0] == "" {
				return 0, false
			}

			index, found = i, true
		}
	}

	return index, len(names) > index && (names[index] == "" || names[index] == keyword)
}
