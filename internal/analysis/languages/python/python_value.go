package python

// A value has one semantic identity, plus independent truth and taint facts.
// In particular a class cannot also be an instance or mapping, and a receiver
// exists only as part of a callable. Unknown semantics use a nil meaning.
type pyValue struct {
	meaning pyMeaning
	truth   uint8
	origins []pyOrigin
}

type pyMeaning interface{ pythonMeaning() }

type (
	pySymbol   string
	pyLiteral  string
	pySequence struct{ items []pyValue }
	pyCallable struct {
		function       *pyFunction
		receiver       *pyValue
		bindingUnknown bool
	}
)

func (pySymbol) pythonMeaning()    {}
func (pyLiteral) pythonMeaning()   {}
func (*pySequence) pythonMeaning() {}
func (*pyCallable) pythonMeaning() {}
func (*pyClass) pythonMeaning()    {}
func (*pyInstance) pythonMeaning() {}
func (*pyMapping) pythonMeaning()  {}
func (*pySuper) pythonMeaning()    {}

func namedValue(name string) pyValue { return pyValue{meaning: pySymbol(name)} }
func functionValue(function *pyFunction) pyValue {
	return pyValue{meaning: &pyCallable{function: function}}
}
func classValue(class *pyClass) pyValue          { return pyValue{meaning: class} }
func instanceValue(instance *pyInstance) pyValue { return pyValue{meaning: instance} }
func superValue(owner *pyClass, receiver pyValue) pyValue {
	return pyValue{meaning: &pySuper{owner: owner, receiver: receiver}}
}

func literalValue(text string, known bool, truth uint8) pyValue {
	value := pyValue{truth: truth}
	if known {
		value.meaning = pyLiteral(text)
	}

	return value
}

func (v pyValue) symbol() string { symbol, _ := v.meaning.(pySymbol); return string(symbol) }
func (v pyValue) literal() (string, bool) {
	literal, ok := v.meaning.(pyLiteral)
	return string(literal), ok
}
func (v pyValue) callable() *pyCallable { callable, _ := v.meaning.(*pyCallable); return callable }
func (v pyValue) function() *pyFunction {
	if callable := v.callable(); callable != nil {
		return callable.function
	}

	return nil
}

func (v pyValue) bound() *pyValue {
	if callable := v.callable(); callable != nil {
		return callable.receiver
	}

	return nil
}
func (v pyValue) class() *pyClass       { class, _ := v.meaning.(*pyClass); return class }
func (v pyValue) instance() *pyInstance { instance, _ := v.meaning.(*pyInstance); return instance }
func (v pyValue) mapping() *pyMapping   { mapping, _ := v.meaning.(*pyMapping); return mapping }
func (v pyValue) super() *pySuper       { super, _ := v.meaning.(*pySuper); return super }
func (v pyValue) elements() []pyValue {
	if sequence, ok := v.meaning.(*pySequence); ok {
		return sequence.items
	}

	return nil
}

func (v pyValue) bind(receiver pyValue) pyValue {
	if callable := v.callable(); callable != nil {
		v.meaning = &pyCallable{
			function:       callable.function,
			receiver:       &receiver,
			bindingUnknown: callable.bindingUnknown,
		}
	}

	return v
}
