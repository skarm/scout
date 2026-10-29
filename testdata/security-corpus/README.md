# Authored security regression cases

`cases.json` contains synthetic data, never commands to execute or plugins to install.
Tests create isolated temporary inputs and scan bytes; no fixture is executed.

Labels distinguish literal threat signals, benign text, ambiguous quotations / authorized
uses, and known static gaps requiring semantic or human review. All expected rule sets are
explicit. The corpus was written with the implementation, is not a holdout, and cannot
establish precision/recall on third-party packages or the quality of any live model.

`known_static_gap` means a deliberately attack-like natural-language case that the current
literal rules DO NOT detect. Passing its regression assertion records a known limit; it
must not be counted as a correctly classified benign case. Offline `allow` is relative to
the limited static profile, not an unrestricted installation recommendation.

Run with `go test -run TestSecurityRegressionCorpus -v .`.
