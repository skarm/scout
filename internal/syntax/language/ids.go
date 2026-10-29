package language

// Canonical language identifiers are output labels; aliases and executable names
// are recognized separately by Normalize and Detect.
const (
	// Unknown identifies unknown.
	Unknown = "unknown"
	// Go identifies go.
	Go = "go"
	// Python identifies python.
	Python = "python"
	// Shell identifies shell.
	Shell = "shell"
	// JavaScript identifies javascript.
	JavaScript = "javascript"
	// TypeScript identifies typescript.
	TypeScript = "typescript"
	// PowerShell identifies powershell.
	PowerShell = "powershell"
	// Batch identifies batch.
	batch = "batch"
	// Ruby identifies ruby.
	Ruby = "ruby"
	// Perl identifies perl.
	Perl = "perl"
	// PHP identifies php.
	PHP = "php"
	// Lua identifies lua.
	Lua = "lua"
	// Rust identifies rust.
	Rust = "rust"
	// C identifies c.
	C = "c"
	// CPP identifies cpp.
	CPP = "cpp"
	// CSharp identifies csharp.
	cSharp = "csharp"
	// Java identifies java.
	Java = "java"
	// Kotlin identifies kotlin.
	kotlin = "kotlin"
	// Swift identifies swift.
	swift = "swift"
	// R identifies r.
	r = "r"
	// SQL identifies sql.
	SQL = "sql"
	// JSON identifies json.
	JSON = "json"
	// YAML identifies yaml.
	YAML = "yaml"
	// TOML identifies toml.
	TOML = "toml"
	// XML identifies xml.
	xml = "xml"
	// HTML identifies html.
	html = "html"
	// INI identifies ini.
	INI = "ini"
	// HCL identifies hcl.
	hcl = "hcl"
	// Dockerfile identifies dockerfile.
	dockerfile = "dockerfile"
	// Makefile identifies makefile.
	makefile = "makefile"
	// GoMod identifies gomod.
	GoMod = "gomod"
	// DependencyManifest identifies dependency-manifest.
	DependencyManifest = "dependency-manifest"
	// Markdown identifies markdown.
	Markdown = "markdown"
	// Text identifies text.
	Text = "text"
)
