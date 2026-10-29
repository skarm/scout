# Exact captured regression fixtures

These ten inert captures pin eight finding regressions plus two non-string
`eval` negative controls. Files are stored as Base64
data and are never executed by the regression test. They are not independent
quality labels or a representative malware corpus.

Source: NVIDIA SkillSpector, commit
`d7338f58200a9ae2a24810cee08911ab68b107a7`, Apache-2.0. See root `NOTICE` and
`licenses/SkillSpector-Apache-2.0.txt`. The fixed capture IDs come from the
existing Scout replay-input capture whose digest is pinned in
`tests/acceptance/provenance_test.go`.

`tests/regression/replay_test.go:TestProductionReplayObservationChanges`
asserts rule IDs, paths and byte spans for every added observation and forbids
JS002 on Promise/Response evaluation arguments. Ordinary scanner rules are
used without fixture-specific detection logic.
