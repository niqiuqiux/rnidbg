# Pull Android 36 (arm64) system bits from a connected device / emulator.
# Usage:  adb must point at an API 36 aarch64 image (GSI or device).
#         Run from repo root:  powershell -File android/sdk36/pull.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Lib64 = Join-Path $Root "system\lib64"
$BinDir = Join-Path $Root "system\bin"
New-Item -ItemType Directory -Force -Path $Lib64 | Out-Null
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$sdk = adb shell getprop ro.build.version.sdk
Write-Host "device sdk=$sdk (expect 36)"

$libs = @(
    "libc.so",
    "libc++.so",
    "libdl.so",
    "liblog.so",
    "libm.so",
    "libstdc++.so",
    "libz.so",
    "libcrypto.so",
    "libssl.so",
    "ld-android.so",
    "libselinux.so",
    "libbase.so",
    "libpackagelistparser.so",
    "libcgrouprc.so",
    "libpcre2.so"
)

foreach ($lib in $libs) {
    $src = "/system/lib64/$lib"
    $dst = Join-Path $Lib64 $lib
    Write-Host "pull $src"
    adb pull $src $dst
}

# Common alias used by some DT_NEEDED entries
$cpp = Join-Path $Lib64 "libc++.so"
$cppAlias = Join-Path $Lib64 "libcpp.so"
if ((Test-Path $cpp) -and -not (Test-Path $cppAlias)) {
    Copy-Item $cpp $cppAlias
}

foreach ($name in @("ls", "sh", "linker64")) {
    $src = "/system/bin/$name"
    $exists = adb shell "test -e $src && echo yes"
    if ($exists -match "yes") {
        # Pull into the directory. A dest file named `ls` is treated as a folder on Windows.
        Write-Host "pull $src"
        adb pull $src $BinDir
    }
}

Write-Host "done. libs in $Lib64"
