module example.invalid/review-fixture

go 1.26.0

require example.invalid/format-lib v1.2.3
replace example.invalid/format-lib => example.invalid/unreviewed-fork v1.2.3
