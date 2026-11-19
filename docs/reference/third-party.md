# Dependencies and licenses

English · [Русский](third-party.ru.md)

Scout's original sources use [MIT](../../LICENSE). Adapted-material attribution is
in [NOTICE](../../NOTICE); full third-party texts are in [licenses](../../licenses).

## Go modules

Pinned modules and checksums are listed in [go.mod](../../go.mod) and [go.sum](../../go.sum). Run `make deps` to download and verify them. Scout requires Go 1.26+. `mvdan.cc/sh/v3` uses BSD-3-Clause. Goldmark uses MIT.

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
