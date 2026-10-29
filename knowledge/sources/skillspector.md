# Source manifest for the trusted validation pack

SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Selected rules and instructions are adapted from NVIDIA SkillSpector. Full license:
`licenses/SkillSpector-Apache-2.0.txt`. This project is not endorsed by NVIDIA.

Retrieved through public source views on 2026-10-26. Those views were cached at
different times; direct DNS access and a complete checkout were unavailable.
There is NO verified common upstream commit. SHA-256 values in this pack's manifest
identify the distributed ADAPTED assets, not the original full Python files and
not a vendor signature. This is source-level adaptation, not behavioral parity.

Later comparison: a complete 464-file snapshot of SkillSpector 2.12.0 at
`d7338f58200a9ae2a24810cee08911ab68b107a7` was obtained and hash-verified on
2026-10-26. This does not retroactively pin the original adaptations above.
The 27 analyzer entrypoints and selected logic were mapped; 12 Scout probes and
two isolated upstream helper calls exposed gaps. At that initial audit stage the
full upstream scanner and live LLM were not run. See `docs/reference/port-manifest.md`.

## Instructions

- `nodes/analyzers/semantic_security_discovery.py`, ANALYZER_PROMPT: SSD-1 through
  SSD-4, residual semantic attacks, confident evidence and benign-discussion caveats.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/semantic_security_discovery.py
- `nodes/analyzers/semantic_developer_intent.py`, ANALYZER_PROMPT: SDI-1 through SDI-4,
  expected implementation details, explicit permission baseline, incomplete versus
  contradictory documentation. The available lower-case repository view is older.
  https://raw.githubusercontent.com/NVIDIA/skillspector/main/src/skillspector/nodes/analyzers/semantic_developer_intent.py
- `nodes/analyzers/semantic_quality_policy.py`, ANALYZER_PROMPT: SQP-1 through SQP-3,
  category-specific file scope and disclosure/context exceptions.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/semantic_quality_policy.py
- `nodes/meta_analyzer.py`, PER_FILE_ANALYSIS_PROMPT: adversarial content boundary,
  finding-by-finding contextual review, intent, impact and guidance.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/meta_analyzer.py

## Deterministic rules and review guidance

- `nodes/analyzers/pattern_defaults.py`: names, explanations and remediations for
  P/E/PE/SC/EA/OH/MP/TM/RA/TR/AST/TT/YR/LP/TP/AS/AR/SSRF families.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/pattern_defaults.py
- `nodes/analyzers/common.py`: code-example context indicators. Here they annotate
  evidence only; they never suppress a finding or change the installation policy.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/common.py
- `nodes/analyzers/static_patterns_prompt_injection.py`: P3/P4 expressions, hidden
  Markdown comments, Unicode tag smuggling, narrowly recognized emoji exceptions.
  An empty regex in a rendered source view is NOT copied as an all-text rule.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/static_patterns_prompt_injection.py
- `nodes/analyzers/static_patterns_supply_chain.py`: SC7 signature/registry bypass,
  SC2/SC3 patterns and _analyze_triggers TR1-TR3 over manifest declarations.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/static_patterns_supply_chain.py
- `nodes/analyzers/static_patterns_data_exfiltration.py`: selected additional E2
  environment-copy/collection and sensitive-key patterns. Literal support is NOT
  the upstream AST extension or a claim that an environment access is exfiltration.
  https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/static_patterns_data_exfiltration.py

## Deliberate adaptations

Output uses scanner-issued excerpt IDs/hashes, not LLM-generated line positions or
free-form explanations. New semantic classes are mapped to their upstream IDs but
remain advisory hypotheses. Quality is a separate opt-in stage. We do not copy the
older meta-analyzer behavior that drops medium/low findings, a confidence threshold
as a calibrated probability, or the suggestion that removing Python __builtins__
creates a security sandbox. Findings are preserved; only trusted operator review
can create exceptions. Prompt text and guidance are embedded build assets, never
loaded from an inspected artifact. Native YARA-X selection is unchanged.

## Scout 0.17 detector transfer

New bounded Go reconstruction, AST10/TT6/DS1-DS4, local Python call/method/C3/super flow,
BH/settings, TP4 and manifest-update logic were transferred against the pinned
comparison commit above. Runtime and exports now include six prompts and 148 guides.
Unicode 17 projection data retains Unicode License V3; 20 bundled YARA rules retain
NVIDIA and derived signature-base DRL-1.1 notices. This describes the historical
0.17 stage; see docs/reference/port-manifest.md.

## Scout 0.18 static differential verification

Both full CLIs were run on 86 identical regression packages against the pinned
comparison commit, with OS network denial and no LLM. All 27 upstream analyzers
loaded, native YARA 4.5.4 was available, and installed upstream package files were
compared to the source snapshot. Confirmed gaps in reconstruction, Python lambda
flow/HTTP bodies, metadata and hook/permission semantics were fixed. Reports retain
raw IDs, severities and unknown coverage; remaining differences are classified.
See docs/reference/port-manifest.md and internal/dev/maintenance/comparison.go. This is not a full-product,
live-model, online-advisory or independent malware-quality parity claim.


## Scout 0.19 full fixture inventory

All 52 fixture files in the pinned source snapshot are now covered as standalone
file inputs and in 34 package directories, including inputs without SKILL.md.
Registry-specific CLI mode and expected invalid-record rejections are recorded
separately. Six authored registry variants supplement the existing regression
cases, for 148 CLI pairs. Five bounded offline registry posture checks were
adapted from mcp_registry.posture_findings, preserving unavailable evidence as
info and treating metadata as untrusted registry assertions. Scanner-generated
JSON token labels no longer create artificial filename-deception findings; raw
bytes and decoded content remain checked and actual archive names stay claims.
See docs/reference/port-manifest.md. Cryptographic signer trust, registry acquisition
and history and the upstream test suite's inline variants are not attested.

## Scout 0.20 whole-suite differential verification

The unmodified pinned upstream suite collected 15,668 cases from 173 test files,
including integration/provider markers. With no public network or live credentials,
15,619 passed, 45 skipped and 4 xfailed. Read-only CPython monitoring captured
110,415 observations, including direct helper calls; raw-byte engine replay and
explicit exclusions are recorded in testdata/provenance/upstream-suite-0.20.json. This does not
mean that every Python assertion or provider contract runs unchanged in Go.

Seven malware rules decoded from src/skillspector/yara_rules/malware.yar.b64 were
missing from the earlier 20-rule inventory. All 27 bundled rules are now present.
Selected reflection/opener, truthy shell, source declaration, padding/stuffing,
state-adoption and prohibition/spacing gaps were corrected with negative controls.
Per-instance ransomware filtering preserves affirmative evidence after a negation.
No complete detector, live-provider or independent quality equivalence is claimed.
