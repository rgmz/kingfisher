@echo off
REM ---------------------------------------------------------------------------
REM  Build a Windows-x64 release of Kingfisher and package it with checksums.
REM
REM  • Installs Hyperscan statically via vcpkg so vectorscan-rs-sys can link
REM    against hs.lib.
REM  • Installs Rust (via Chocolatey) if missing.
REM  • Call with -force to clone & bootstrap vcpkg if it isn’t found.
REM ---------------------------------------------------------------------------

setlocal EnableDelayedExpansion

REM ── Project name ────────────────────────────────────────────────────────────
set "PROJECT_NAME=kingfisher"

REM ── Require Windows ─────────────────────────────────────────────────────────
if NOT "%OS%"=="Windows_NT" (
    echo This script must be run on Windows.
    exit /b 1
)

REM ── Locate MSVC toolchain ───────────────────────────────────────────────────
if "%VCINSTALLDIR%"=="" (
    echo VCINSTALLDIR not set — attempting auto-detection...
    for %%P in (
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC"
    ) do if exist "%%~P\Auxiliary\Build\vcvars64.bat" (
        set "VCINSTALLDIR=%%~P"
        echo Found Visual C++ Build Tools at: %%~P
        goto :vc_found
    )
    echo ERROR: Could not find a suitable Visual Studio installation.
    echo        Install “Desktop development with C++” or set VCINSTALLDIR.
    exit /b 1
)
:vc_found
if "%VCINSTALLDIR:~-1%"=="\" set "VCINSTALLDIR=%VCINSTALLDIR:~0,-1%"

echo Initialising MSVC environment…
call "%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat" || (
    echo ERROR: Failed to initialise MSVC toolchain.
    exit /b 1
)

REM ── Locate or bootstrap vcpkg ───────────────────────────────────────────────
where vcpkg.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "%HOMEDRIVE%\vcpkg\vcpkg.exe" (
        set "VCPKG_EXE=%HOMEDRIVE%\vcpkg\vcpkg.exe"
    ) else if "%~1"=="-force" (
        echo Cloning and bootstrapping vcpkg…
        if exist "%HOMEDRIVE%\vcpkg" rmdir /s /q "%HOMEDRIVE%\vcpkg"
        git clone https://github.com/microsoft/vcpkg.git "%HOMEDRIVE%\vcpkg"
        pushd "%HOMEDRIVE%\vcpkg"
        call .\bootstrap-vcpkg.bat || (echo ERROR: vcpkg bootstrap failed.&exit /b 1)
        set "VCPKG_EXE=%CD%\vcpkg.exe"
        popd
    ) else (
        echo ERROR: vcpkg not found. Install it or rerun with -force.
        exit /b 1
    )
) else (
    for /f "tokens=*" %%i in ('where vcpkg.exe') do set "VCPKG_EXE=%%i"
)

echo Found vcpkg at: !VCPKG_EXE!

REM  Derive vcpkg root
for %%i in ("!VCPKG_EXE!") do set "VCPKG_ROOT=%%~dpi"
if "!VCPKG_ROOT:~-1!"=="\" set "VCPKG_ROOT=!VCPKG_ROOT:~0,-1!"

REM ── Ensure LOCALAPPDATA has a drive letter (GitHub Actions quirk) ───────────
if /I not "%LOCALAPPDATA:~1,1%"==":" (
    echo LOCALAPPDATA lacks drive letter; pointing it at APPDATA.
    set "LOCALAPPDATA=%APPDATA%"
)

REM ── Install Hyperscan statically ────────────────────────────────────────────
set "VCPKG_TRIPLET=x64-windows-static"
echo Installing Hyperscan (!VCPKG_TRIPLET!) via vcpkg…

pushd "!VCPKG_ROOT!"
"!VCPKG_EXE!" install hyperscan:!VCPKG_TRIPLET! --clean-after-build || (
    echo ERROR: vcpkg install failed.
    popd
    exit /b 1
)
popd

set "LIBHS_NO_PKG_CONFIG=1"

REM Path hints for vectorscan-rs-sys
set "HYPERSCAN_ROOT=!VCPKG_ROOT!\installed\!VCPKG_TRIPLET!"
set "LIB=!HYPERSCAN_ROOT!\lib;%LIB%"
set "INCLUDE=!HYPERSCAN_ROOT!\include;%INCLUDE%"

REM Fallback: rename vectorscan.lib -> hs.lib if vcpkg changed the name
if not exist "!HYPERSCAN_ROOT!\lib\hs.lib" if exist "!HYPERSCAN_ROOT!\lib\vectorscan.lib" (
    copy "!HYPERSCAN_ROOT!\lib\vectorscan.lib" "!HYPERSCAN_ROOT!\lib\hs.lib" >nul
)

REM ── Install Rust toolchain if absent ────────────────────────────────────────
where rustc.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Rust via Chocolatey…
    choco install rust-ms -y || exit /b 1
    choco install cmake -y --installargs "ADD_CMAKE_TO_PATH=System" || exit /b 1
    call refreshenv
) else (
    echo Rust is already installed.
)

REM ── Build ───────────────────────────────────────────────────────────────────
echo Building for Windows x64…
cargo build --release --target x86_64-pc-windows-msvc || (
    echo ERROR: Cargo build failed.
    exit /b 1
)

REM ── Package & checksum ──────────────────────────────────────────────────────
echo Generating CHECKSUM.txt…
powershell -Command ^
  "Get-FileHash .\target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe -Algorithm SHA256 | Out-File .\target\x86_64-pc-windows-msvc\release\CHECKSUM.txt"

if not exist "target\release" mkdir "target\release"
copy /Y "target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe"           "target\release\" >nul
copy /Y "target\x86_64-pc-windows-msvc\release\CHECKSUM.txt"                "target\release\CHECKSUM-windows-x64.txt" >nul

pushd target\release
echo Creating archive: %PROJECT_NAME%-windows-x64.zip
if exist "%PROJECT_NAME%-windows-x64.zip" del /f /q "%PROJECT_NAME%-windows-x64.zip"
powershell -Command "Compress-Archive -Path '%PROJECT_NAME%.exe','CHECKSUM-windows-x64.txt' -DestinationPath '%PROJECT_NAME%-windows-x64.zip' -Force"

if exist "%PROJECT_NAME%-windows-x64.zip" (
    certutil -hashfile "%PROJECT_NAME%-windows-x64.zip" SHA256 >> "CHECKSUM-windows-x64.txt"
    echo Created: %PROJECT_NAME%-windows-x64.zip
) else (
    echo ERROR: Archive not created.
)
echo Archives in target\release:
dir /b *.zip 2>nul || echo None found.
popd

endlocal
exit /b 0
