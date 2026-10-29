package python

import (
	"sort"
)

type pyValuePair struct {
	xm, ym *pyMapping
	xi, yi *pyInstance
	xs, ys *pySequence
}

type pyFork struct {
	states                   map[*pyState]*pyState
	seen                     map[*pyInstance]*pyInstance
	sequences                map[*pySequence]*pySequence
	mappings                 map[*pyMapping]*pyMapping
	originalObjects, objects *pyObjectStore
}

// Branch/definition exploration must not mutate shared instance fields. Keep
// aliases inside a fork, then conservatively join both possible field states.
func (s *pyState) fork() *pyState {
	c := pyFork{
		states:          map[*pyState]*pyState{},
		seen:            map[*pyInstance]*pyInstance{},
		sequences:       map[*pySequence]*pySequence{},
		mappings:        map[*pyMapping]*pyMapping{},
		originalObjects: s.objects,
		objects: &pyObjectStore{
			classes:  map[*pyClass]map[string]pyValue{},
			defaults: map[*pyFunction]map[string]pyValue{},
		},
	}

	state := c.state(s, 0)
	for function := range s.objects.defaults {
		c.functionDefaults(function, 0)
	}

	return state
}

func (c *pyFork) value(v pyValue, depth int) pyValue {
	if depth > 32 {
		return pyValue{origins: v.origins}
	}

	switch meaning := v.meaning.(type) {
	case *pySequence:
		v.meaning = c.sequence(meaning, depth)
	case *pyInstance:
		v.meaning = c.instance(meaning, depth)
	case *pyMapping:
		v.meaning = c.mapping(meaning, depth)
	case *pyClass:
		c.classAttributes(meaning, depth)
	case *pySuper:
		v.meaning = &pySuper{owner: meaning.owner, receiver: c.value(meaning.receiver, depth+1)}
	case *pyCallable:
		c.functionDefaults(meaning.function, depth)

		if meaning.receiver != nil {
			receiver := c.value(*meaning.receiver, depth+1)
			v.meaning = &pyCallable{
				function:       meaning.function,
				receiver:       &receiver,
				bindingUnknown: meaning.bindingUnknown,
			}
		}
	}

	return v
}

func (c *pyFork) sequence(original *pySequence, depth int) *pySequence {
	if existing := c.sequences[original]; existing != nil {
		return existing
	}

	sequence := &pySequence{items: make([]pyValue, len(original.items))}

	c.sequences[original] = sequence
	for i, item := range original.items {
		sequence.items[i] = c.value(item, depth+1)
	}

	return sequence
}

func (c *pyFork) instance(original *pyInstance, depth int) *pyInstance {
	if existing := c.seen[original]; existing != nil {
		return existing
	}

	instance := &pyInstance{typ: original.typ, fields: map[string]pyValue{}}
	c.seen[original] = instance
	c.classAttributes(original.typ, depth)

	for key, field := range original.fields {
		instance.fields[key] = c.value(field, depth+1)
	}

	return instance
}

func (c *pyFork) mapping(original *pyMapping, depth int) *pyMapping {
	if existing := c.mappings[original]; existing != nil {
		return existing
	}

	mapping := &pyMapping{entries: map[string]pyValue{}}

	c.mappings[original] = mapping
	for key, item := range original.entries {
		mapping.entries[key] = c.value(item, depth+1)
	}

	return mapping
}

func (c *pyFork) classAttributes(class *pyClass, depth int) {
	if class == nil {
		return
	}

	for _, base := range class.mro {
		if c.objects.classes[base] != nil {
			continue
		}

		attrs := base.attrs
		if changed := c.originalObjects.classes[base]; changed != nil {
			attrs = changed
		}

		cloned := map[string]pyValue{}

		c.objects.classes[base] = cloned
		for name, value := range attrs {
			cloned[name] = c.value(value, depth+1)
		}
	}
}

func (c *pyFork) functionDefaults(function *pyFunction, depth int) {
	if function == nil || c.objects.defaults[function] != nil {
		return
	}

	defaults := c.originalObjects.defaults[function]
	if defaults == nil {
		defaults = function.defaults
	}

	cloned := map[string]pyValue{}

	c.objects.defaults[function] = cloned
	for name, value := range defaults {
		cloned[name] = c.value(value, depth+1)
	}
}

func (c *pyFork) state(old *pyState, depth int) *pyState {
	if old == nil {
		return nil
	}

	if existing := c.states[old]; existing != nil {
		return existing
	}

	r := old.clone()
	r.objects = c.objects

	c.states[old] = r
	if depth > 32 {
		clear(r.names)
		r.blockedBuiltins = true
		r.parent = nil
		r.global = r

		return r
	}

	r.parent, r.global = c.state(old.parent, depth+1), c.state(old.global, depth+1)
	for k, v := range r.names {
		r.names[k] = c.value(v, 0)
	}

	for original, mapped := range old.forks {
		if c.states[original] == nil {
			c.states[original] = c.state(mapped, depth+1)
		}
	}

	r.forks = c.states

	return r
}

// Containers can be aliased and changed after binding. Refresh their taint
// from current contents, with a depth cap for cyclic mappings.
func pyContents(v pyValue) pyValue {
	seen := map[*pyMapping]bool{}

	var collect func(pyValue, int) pyValue

	collect = func(item pyValue, depth int) pyValue {
		if item.mapping() == nil {
			return item
		}

		if depth > 16 || seen[item.mapping()] {
			return joinPy(item)
		}

		seen[item.mapping()] = true

		out := pyValue{}
		for _, key := range sortedPyKeys(item.mapping().entries) {
			out = joinPy(out, collect(item.mapping().entries[key], depth+1))
		}

		return out
	}
	if v.mapping() != nil {
		v.origins = collect(v, 0).origins
	}

	return v
}

// Join branch effects in the current namespace and in explicitly reachable
// global/nonlocal owners. Forks redirect function closures without cloning
// function identities or allowing hypothetical definition scans to write back.
func mergePyBranches(s, a, b *pyState) {
	memo := map[pyValuePair]pyValue{}
	r := mergePy(a, b, memo)

	visited := map[*pyState]bool{s: true}
	for _, root := range []*pyState{s.parent, s.global} {
		for owner := root; owner != nil && !visited[owner]; owner = owner.parent {
			visited[owner] = true

			x, y := a.forks[owner], b.forks[owner]
			if x == nil {
				x = owner
			}

			if y == nil {
				y = owner
			}

			merged := mergePy(x, y, memo)
			owner.names, owner.blockedBuiltins = merged.names, merged.blockedBuiltins
		}
	}

	r.parent, r.global, r.forks = s.parent, s.global, s.forks
	s.objects.classes = r.objects.classes
	s.objects.defaults = r.objects.defaults
	r.objects = s.objects
	*s = *r
}

func mergeObjectStores(a, b *pyObjectStore, memo map[pyValuePair]pyValue) *pyObjectStore {
	return &pyObjectStore{
		classes:  mergeObjectFields(a.classes, b.classes, func(class *pyClass) map[string]pyValue { return class.attrs }, memo),
		defaults: mergeObjectFields(a.defaults, b.defaults, func(function *pyFunction) map[string]pyValue { return function.defaults }, memo),
	}
}

func mergeObjectFields[K comparable](a, b map[K]map[string]pyValue, initial func(K) map[string]pyValue, memo map[pyValuePair]pyValue) map[K]map[string]pyValue {
	merged := map[K]map[string]pyValue{}
	for object := range a {
		merged[object] = map[string]pyValue{}
	}

	for object := range b {
		merged[object] = map[string]pyValue{}
	}

	for object, attrs := range merged {
		x, y := a[object], b[object]
		if x == nil {
			x = initial(object)
		}

		if y == nil {
			y = initial(object)
		}

		mergePyFields(attrs, x, y, 0, memo)
	}

	return merged
}

func sortedPyKeys(entries map[string]pyValue) []string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func mergePyValue(x, y pyValue) pyValue {
	return mergePyValueMemo(x, y, 0, map[pyValuePair]pyValue{})
}

func mergePyValueMemo(x, y pyValue, depth int, memo map[pyValuePair]pyValue) pyValue {
	xs, _ := x.meaning.(*pySequence)
	ys, _ := y.meaning.(*pySequence)
	key := pyValuePair{xm: x.mapping(), ym: y.mapping(), xi: x.instance(), yi: y.instance(), xs: xs, ys: ys}

	container := key != (pyValuePair{})
	if container {
		if old, ok := memo[key]; ok {
			return old
		}
	}

	z := mergePyScalars(x, y, depth, memo)

	return mergePyContainers(x, y, z, depth, memo, key, container)
}

func mergePyScalars(x, y pyValue, depth int, memo map[pyValuePair]pyValue) pyValue {
	z := joinPy(x, y)
	if x.truth == y.truth {
		z.truth = x.truth
	}

	switch meaning := x.meaning.(type) {
	case pySymbol, pyLiteral, *pyClass:
		if x.meaning == y.meaning {
			z.meaning = meaning
		}
	case *pyCallable:
		z.meaning = mergeCallable(meaning, y.callable(), depth, memo)
	case *pySuper:
		other := y.super()
		if other != nil && other.owner == meaning.owner && depth < 16 {
			z.meaning = &pySuper{
				owner:    meaning.owner,
				receiver: mergePyValueMemo(meaning.receiver, other.receiver, depth+1, memo),
			}
		}
	}

	return z
}

func mergeCallable(x, y *pyCallable, depth int, memo map[pyValuePair]pyValue) pyMeaning {
	if y == nil || x.function != y.function {
		return nil
	}

	callable := &pyCallable{function: x.function, bindingUnknown: x.bindingUnknown || y.bindingUnknown}
	if x.receiver == y.receiver {
		callable.receiver = x.receiver
	} else if x.receiver != nil && y.receiver != nil {
		receiver := mergePyValueMemo(*x.receiver, *y.receiver, depth+1, memo)
		callable.receiver = &receiver
	} else {
		callable.bindingUnknown = true
	}

	return callable
}

func mergePyContainers(x, y, z pyValue, depth int, memo map[pyValuePair]pyValue, key pyValuePair, container bool) pyValue {
	if meaning := mergedContainerShape(x, y, depth); meaning != nil {
		z.meaning = meaning
	}

	if container {
		memo[key] = z
	}

	fillMergedContainer(x, y, z, depth, memo)

	return z
}

func mergedContainerShape(x, y pyValue, depth int) pyMeaning {
	switch meaning := x.meaning.(type) {
	case *pyMapping:
		if y.mapping() != nil && depth < 16 {
			return &pyMapping{entries: map[string]pyValue{}}
		}
	case *pySequence:
		if len(meaning.items) > 0 && len(meaning.items) == len(y.elements()) && depth < 16 {
			return &pySequence{items: make([]pyValue, len(meaning.items))}
		}
	case *pyInstance:
		return mergedInstanceShape(meaning, y.instance(), depth)
	}

	return nil
}

func mergedInstanceShape(x, y *pyInstance, depth int) pyMeaning {
	if x == y {
		return x
	}

	if y != nil && x.typ == y.typ && depth < 16 {
		return &pyInstance{typ: x.typ, fields: map[string]pyValue{}}
	}

	return nil
}

func fillMergedContainer(x, y, z pyValue, depth int, memo map[pyValuePair]pyValue) {
	switch meaning := z.meaning.(type) {
	case *pyMapping:
		mergePyFields(meaning.entries, x.mapping().entries, y.mapping().entries, depth, memo)
	case *pySequence:
		for i, item := range x.elements() {
			meaning.items[i] = mergePyValueMemo(item, y.elements()[i], depth+1, memo)
		}
	case *pyInstance:
		if x.instance() != y.instance() {
			mergePyFields(meaning.fields, x.instance().fields, y.instance().fields, depth, memo)
		}
	}
}

func mergePyFields(out, x, y map[string]pyValue, depth int, memo map[pyValuePair]pyValue) {
	for k, v := range x {
		out[k] = mergePyValueMemo(v, y[k], depth+1, memo)
	}

	for k, v := range y {
		if _, ok := x[k]; !ok {
			out[k] = mergePyValueMemo(pyValue{}, v, depth+1, memo)
		}
	}
}
