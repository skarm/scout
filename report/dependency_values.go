package report

// Dependency vocabulary describes declarations without claiming an installed graph.
const (
	// EcosystemGo identifies Go.
	EcosystemGo = "Go"
	// EcosystemNPM identifies npm.
	EcosystemNPM = "npm"
	// EcosystemPyPI identifies PyPI.
	EcosystemPyPI = "PyPI"
	// VersionExactLockfile records an exact version declared in a lockfile.
	VersionExactLockfile = "exact-lockfile"
	// VersionExactDeclaration records exact version text without proving installation.
	VersionExactDeclaration = "exact-declaration-not-install-evidence"
	// VersionUnresolved retains a declaration whose range or source was not resolved.
	VersionUnresolved = "range-or-source-unresolved"
	// VersionGoMinimum records a Go minimum version without resolving MVS.
	VersionGoMinimum = "declared-minimum-unresolved-MVS"
)
