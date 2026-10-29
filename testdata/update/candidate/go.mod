module example.invalid/update-fixture

go 1.26.0

require example.invalid/helper v1.2.3

replace example.invalid/helper => example.invalid/different-source v1.2.4
