package bundle

import (
	"errors"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
)

const (
	resolverGo = iota + 1
	resolverNode
	resolverPython
	resolverPythonAsync
)

// Aliases share invalidation state, so replacing a method through one alias
// cannot leave another alias with a stale, trusted resolver method identity.
type bundleResolver struct {
	kind    int
	invalid bool
}

func (b *bundleAnalysis) resolverConstructor(p *bundleProgram, n *bundleNode, name string, args []bundleValue) (bundleValue, bool) {
	kind := 0

	switch p.language {
	case language.JavaScript, language.TypeScript:
		switch name {
		case "dns.Resolver", "dns.promises.Resolver", "dns/promises.Resolver":
			if n.kind != nodeConstruct || len(args) > 1 {
				b.gap = errors.New("resolver constructor invocation is unresolved")
				return bundleValue{}, true
			}

			kind = resolverNode
		}
	case language.Go:
		if name == "new" && len(args) == 1 && args[0].name == "net.Resolver" {
			kind = resolverGo
		}
	case language.Python:
		switch name {
		case "dns.resolver.Resolver":
			kind = resolverPython
		case "dns.asyncresolver.Resolver":
			kind = resolverPythonAsync
		}
	}

	if kind == 0 {
		return bundleValue{}, false
	}

	return bundleValue{resolver: &bundleResolver{kind: kind}}, true
}

func (b *bundleAnalysis) resolverLiteral(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	var typ bundleValue

	for i, child := range n.children {
		v := b.eval(p, child, env, depth+1)
		if b.err != nil {
			return bundleValue{}
		}

		if i == 0 {
			typ = v
		}
	}

	if typ.name != "net.Resolver" {
		b.gap = errors.New("resolver literal type is unresolved")
		return bundleValue{}
	}

	return bundleValue{resolver: &bundleResolver{kind: resolverGo}}
}

func (b *bundleAnalysis) evalResolverNode(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	switch n.kind {
	case nodeResolver:
		return b.resolverLiteral(p, n, env, depth)
	case nodeWrite:
		return b.resolverWrite(p, n, env, depth)
	default:
		v := b.eval(p, n.children[0], env, depth+1)
		if v.resolver != nil && v.name == "" {
			return v
		}

		return mergeBundleValue(bundleValue{}, v)
	}
}

func (b *bundleAnalysis) resolverMember(p *bundleProgram, v bundleValue, property string, at *bundleNode) (bundleValue, bool) {
	if v.resolver != nil {
		if v.resolver.invalid || v.name != "" || property == "" {
			b.gap = errors.New("resolver member or binding is unresolved")
			return bundleValue{uncertainFunction: true}, true
		}

		return bundleValue{resolver: v.resolver, name: property, resolverReceiver: at}, true
	}

	if p.language == language.Go && v.name == "net" && property == "DefaultResolver" {
		if b.defaultResolver == nil {
			b.defaultResolver = &bundleResolver{kind: resolverGo}
		}

		return bundleValue{resolver: b.defaultResolver}, true
	}

	return bundleValue{}, false
}

func resolverDNS(kind int, method string) ([]int, string) {
	switch kind {
	case resolverNode:
		if strings.HasPrefix(method, "resolve") {
			return bundleDNS("dns."+method, language.JavaScript)
		}
	case resolverGo:
		return bundleDNS("net.DefaultResolver."+method, language.Go)
	case resolverPython, resolverPythonAsync:
		switch method {
		case "resolve":
			return []int{0}, "qname"
		case "query":
			if kind == resolverPython {
				return []int{0}, "qname"
			}
		case "resolve_name", "canonical_name":
			return []int{0}, "name"
		}
	}

	return nil, ""
}

func resolverControl(kind int, method string) bool {
	if kind == resolverNode {
		switch method {
		case "setServers", "getServers", "cancel", "setLocalAddress":
			return true
		}
	}

	return kind == resolverGo && method == "LookupPort"
}

func (b *bundleAnalysis) resolverWrite(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	if len(n.children) < 2 {
		return bundleValue{}
	}

	var value bundleValue
	if n.valueFirst {
		value = b.eval(p, n.children[len(n.children)-1], env, depth+1)
	}

	receiver := b.eval(p, n.children[0], env, depth+1)

	property, known := n.name, n.known
	if !known && len(n.children) > 2 {
		key := b.eval(p, n.children[1], env, depth+1)
		property, known = key.text, key.known
	}

	if !n.valueFirst {
		value = b.eval(p, n.children[len(n.children)-1], env, depth+1)
	}

	if b.err != nil {
		return bundleValue{}
	}

	if receiver.resolver != nil {
		if !known || !resolverConfig(receiver.resolver.kind, property) {
			receiver.resolver.invalid = true
			b.gap = errors.New("resolver member mutation is unresolved")
		} else if receiver.resolver.kind == resolverGo && property == "Dial" {
			b.gap = errors.New("custom Go resolver dialer is unresolved")
		}
	} else if receiver.module != nil || receiver.uncertainFunction || dnsModuleName(p.language, receiver.name) {
		// Namespace writes can replace constructors or exports across frames.
		// Stop before another frame observes a stale module identity.
		b.err = errors.New("DNS or captured module mutation is unresolved")
		b.globalWriteStop = true
	} else if n.globalWrite {
		b.err = errors.New("script global binding writes are unresolved")
		b.globalWriteStop = true
	}

	return value
}

func dnsModuleName(lang, name string) bool {
	switch lang {
	case language.JavaScript, language.TypeScript:
		name = strings.TrimSuffix(name, ".prototype")
		return name == "dns" || name == "dns.promises" || name == "dns/promises" || name == "dns.Resolver" || name == "dns.promises.Resolver" || name == "dns/promises.Resolver"
	case language.Go:
		return name == "net"
	case language.Python:
		return name == "dns" || name == "dns.resolver" || name == "dns.asyncresolver" || name == "dns.resolver.Resolver" || name == "dns.asyncresolver.Resolver"
	}

	return false
}

func resolverConfig(kind int, property string) bool {
	switch kind {
	case resolverGo:
		return property == "PreferGo" || property == "StrictErrors" || property == "Dial"
	case resolverPython, resolverPythonAsync:
		switch property {
		case "nameservers", "port", "timeout", "lifetime", "search", "use_search_by_default":
			return true
		}
	}

	return false
}
