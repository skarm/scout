# Build the pinned C API with the same GNU ABI used by Go's Windows CGO toolchain.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$source = Join-Path $env:GITHUB_WORKSPACE '.work/yara-x'
$prefix = Join-Path $env:RUNNER_TEMP 'yara-x-native'
$evidence = Join-Path $env:RUNNER_TEMP 'native-evidence'
$toolchain = '1.95.0-x86_64-pc-windows-gnu'
$target = 'x86_64-pc-windows-gnu'

if ((git -C $source rev-parse HEAD) -ne 'e27597f2c05e13fe1c2bb459781aef8899afc485') {
    throw 'YARA-X source revision differs from the reviewed v1.22.0 pin'
}
New-Item -ItemType Directory -Force $evidence, "$prefix/include", "$prefix/lib/pkgconfig" | Out-Null

rustup toolchain install $toolchain --profile minimal
rustc "+$toolchain" --version | Set-Content "$evidence/rust-version.txt"
gcc --version | Set-Content "$evidence/cc-version.txt"
pkg-config --version | Set-Content "$evidence/pkg-config-version.txt"
git -C $source rev-parse HEAD | Set-Content "$evidence/yara-x-commit.txt"

Push-Location $source
try {
    cargo "+$toolchain" metadata --locked --format-version 1 --filter-platform $target |
        Set-Content -Encoding utf8NoBOM "$evidence/yara-x-metadata.json"
    # --locked verifies Cargo.lock; rustc reports the native libraries needed
    # when another language links the resulting Rust static archive.
    cargo "+$toolchain" rustc --locked --release --package yara-x-capi --target $target -- --print native-static-libs 2>&1 |
        Tee-Object -FilePath "$evidence/yara-x-build.log"
} finally {
    Pop-Location
}

$match = Select-String -Path "$evidence/yara-x-build.log" -Pattern 'native-static-libs:\s*(.+)$' | Select-Object -Last 1
if (-not $match) { throw 'Rust did not report the static C API linker dependencies' }
$libraries = $match.Matches[0].Groups[1].Value.Trim()
Copy-Item "$source/target/$target/release/libyara_x_capi.a" "$prefix/lib/"
Copy-Item "$source/capi/include/yara_x.h" "$prefix/include/"
Copy-Item "$source/LICENSE" "$prefix/LICENSE"
Copy-Item "$source/Cargo.lock" "$evidence/yara-x-Cargo.lock"

# Forward slashes work with both native Windows pkgconf and Go. Use an absolute
# prefix so that no MSYS path translation is needed by the native Go process.
$posixPrefix = $prefix.Replace('\', '/')
@"
prefix=$posixPrefix
libdir=`${prefix}/lib
includedir=`${prefix}/include

Name: yara_x_capi
Description: Pinned YARA-X static C API
Version: 1.22.0
Libs: -L`"`${libdir}`" -lyara_x_capi
Libs.private: $libraries
Cflags: -I`"`${includedir}`"
"@ | Set-Content -Encoding utf8NoBOM "$prefix/lib/pkgconfig/yara_x_capi.pc"

"PKG_CONFIG_PATH=$prefix/lib/pkgconfig" | Add-Content $env:GITHUB_ENV
"SCOUT_YARA_PREFIX=$prefix" | Add-Content $env:GITHUB_ENV
