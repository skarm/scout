package shellsyntax

// Part kinds shared by the parser and the shell analysis consumers.
const (
	PartArithmetic                    = "arithmetic"
	PartArithmeticVariable            = "arithmetic_variable"
	PartLiteral                       = "literal"
	PartParameter                     = "parameter"
	PartParameterArrayAll             = "parameter_array_all"
	PartParameterArrayAllDefaultEmpty = "parameter_array_all_default_empty"
	PartParameterBashSource           = "parameter_bash_source"
	PartParameterDefaultDot           = "parameter_default_dot"
	PartParameterDefaultEmpty         = "parameter_default_empty"
	PartParameterIndirect             = "parameter_indirect"
	PartParameterLength               = "parameter_length"
	PartParameterReplaceAll           = "parameter_replace_all"
	PartParameterScriptDir            = "parameter_script_dir"
	PartParameterTrimNewline          = "parameter_trim_newline"
	PartParameterValue                = "parameter_value"
	PartProcessSubstitution           = "process_substitution"
	PartSubstitution                  = "substitution"
)

// Parameter expansion forms.
const (
	partParameterArrayJoin = "parameter_array_join"
	partParameterIndex     = "parameter_index"
)
