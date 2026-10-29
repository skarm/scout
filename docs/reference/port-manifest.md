# Sources and adapted materials

English · [Русский](port-manifest.ru.md)

Scout adapts selected materials for its own analyzers and review workflow.
Rule names alone do not establish behavioral equivalence with upstream.

## NVIDIA SkillSpector

Adaptations include selected patterns, detector concepts, 27 YARA rules, review
prompts, guidance and the Skill Inspector workflow. Attribution is preserved in
[NOTICE](../../NOTICE) and the [Apache-2.0 license](../../licenses/SkillSpector-Apache-2.0.txt).

Detailed provenance lives in `knowledge/sources/skillspector.md`, guidance source
references and `internal/distribution/integrations/sources/transfer-manifest.json`.
Historical adaptations include cached/main views and are not all bound to one
upstream commit. The pinned comparison inventory is in
`testdata/provenance/upstream-inventory.json`.

## Cisco

Eight YARA rules were adapted from
[Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner/tree/f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1).
The pack is `internal/signatures/rules/cisco_adapted.yar`. Source hashes are in the
[receipt](../../testdata/provenance/cisco-hardening-2026-10-29.json).
Copyright and Apache-2.0 notices remain in [NOTICE](../../NOTICE) and the
[Cisco license](../../licenses/Cisco-Apache-2.0.txt).

## Reference material

[Snyk agent-scan](https://github.com/snyk/agent-scan/tree/a69e1c354ad0812c13da15dc64770e1c21786841)
informed tool-collision and capability-combination comparisons. Its client and
backend are not included. Authored review criteria use pinned references recorded
in `knowledge/data/review_sources.json`; see [knowledge topics](curated-knowledge.md).

## Verification and redistribution

Saved comparisons bind specific sources and hashes. Reproduction commands are in
the [developer guide](../development/commands.md). They do not establish detection
parity or independent accuracy. Retain applicable LICENSE/NOTICE files when redistributing
adaptations. See [dependency licenses](third-party.md).
