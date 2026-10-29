$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$candidate = Join-Path $env:RUNNER_TEMP 'candidate'
$evidence = Join-Path $env:RUNNER_TEMP 'native-evidence'
New-Item -ItemType Directory -Force $candidate, $evidence | Out-Null

go version | Set-Content "$evidence/go-version.txt"
go mod download -json | Set-Content "$evidence/module-downloads.json"
go mod verify
git diff --exit-code -- go.mod go.sum
Copy-Item go.mod, go.sum $evidence
go list -m -json all | Set-Content "$evidence/modules.json"
$env:GOPROXY = 'off'

# All commands use the existing dependency wrapper and full native backends.
go run -mod=readonly ./internal/dev/builddeps -- go test -vet=off -mod=readonly -count=1 -timeout=15m ./... 2>&1 |
    Tee-Object -FilePath "$evidence/tests.log"
go run -mod=readonly ./internal/dev/builddeps -- go test -vet=off -mod=readonly -race -count=1 -timeout=20m ./... 2>&1 |
    Tee-Object -FilePath "$evidence/race.log"

$binary = Join-Path $candidate 'scout.exe'
go run -mod=readonly ./internal/dev/builddeps -- go build -mod=readonly -trimpath "-ldflags=-s -w -X github.com/skarm/scout.buildVersionOverride=$env:VERSION" -o $binary ./cmd/scout
if ((& $binary version) -ne $env:VERSION) { throw 'Release version was not embedded' }
& $binary capabilities | Set-Content -Encoding utf8NoBOM "$evidence/capabilities.json"
go run -mod=readonly ./internal/dev/builddeps -- go run -mod=readonly "-ldflags=-X github.com/skarm/scout.buildVersionOverride=$env:VERSION" ./cmd/scout-dev releasecheck --binary $binary |
    Tee-Object -FilePath "$evidence/releasecheck.json"

$hash = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
"$hash  scout.exe" | Set-Content -Encoding ascii "$candidate/scout.sha256"
