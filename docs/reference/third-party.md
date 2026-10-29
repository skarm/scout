# Dependencies and licenses

English · [Русский](third-party.ru.md)

Scout's original sources use [MIT](../../LICENSE). Adapted-material attribution is
in [NOTICE](../../NOTICE); full third-party texts are in [licenses](../../licenses).

## Go modules

[go.mod](../../go.mod) and [go.sum](../../go.sum) pin these versions:

- YARA-X Go: 1.22.0.
- `go-toml/v2`: 2.4.3; `go.yaml.in/yaml/v3`: 3.0.5.
- `go-tree-sitter`, Python and JavaScript grammars: 0.25.0; TypeScript: 0.23.2.
- `mvdan.cc/sh/v3`: 3.14.1, BSD-3-Clause; syntax parser without the interpreter.
- `x/mod`: 0.42.0; `x/sys`: 0.49.0.
- Indirect: `go-pointer`: 0.0.1; protobuf: 1.36.12.

`make deps` downloads and verifies modules. Minimum Go version is 1.26.0.

## Native dependencies

Full builds use Tree-sitter and YARA-X C API 1.22.0.
See [build preparation](../development/native-build.md).
`internal/syntax/treeparse/tree_sitter_api.h` is copied unchanged from go-tree-sitter
v0.25.0 and covered by `licenses/go-tree-sitter-MIT.txt`.
Native and Go dependency licenses apply to binary redistribution.

## Embedded materials

- NVIDIA SkillSpector and Cisco skill-scanner adaptations: Apache-2.0.
- Derived signature-base patterns: Detection Rule License 1.1.
- Unicode normalization/confusables data: Unicode License V3.
- JS/TS grammars: MIT.

See [provenance](port-manifest.md) for source references.
Exported host bundles include their own LICENSE/NOTICE files and package.json peer ranges.
