@echo off
REM ============================================================================
REM buildwin.bat — Windows x64 release build + archive for Kingfisher
REM - Robustly finds/bootstraps vcpkg at a predictable root (prefers C:\vcpkg)
REM - Installs Hyperscan for x64-windows-static into that root
REM - Points LIB/INCLUDE to the installed Hyperscan and verifies hs.lib exists
REM - Builds a static CRT binary (x86_64-pc-windows-msvc), zips & checksums it
REM
REM Usage:
REM   buildwin.bat             (normal CI usage)
REM   buildwin.bat -force      (re-clone/rebootstrap vcpkg into VCPKG_ROOT)
REM
REM You can override these via environment variables if desired:
REM   PROJECT_NAME (default: kingfisher)
REM   VCPKG_ROOT   (default: auto-detected; prefers C:\vcpkg)
REM   VCPKG_TRIPLET (default: x64-windows-static)
REM ============================================================================

setlocal
set "PROJECT_NAME=kingfisher"
if not "%~1"=="" (
  if /I "%~1"=="-force" ( set "FORCE_VCPKG=1" ) else ( set "FORCE_VCPKG=0" )
) else (
  set "FORCE_VCPKG=0"
)

if "%VCPKG_TRIPLET%"=="" set "VCPKG_TRIPLET=x64-windows-static"

REM ── Check OS ────────────────────────────────────────────────────────────────
if NOT "%OS%"=="Windows_NT" (
    echo This script must be run on Windows.
    exit /b 1
)

REM ── Ensure MSVC/VS environment ─────────────────────────────────────────────
if "%VCINSTALLDIR%"=="" (
    echo VCINSTALLDIR not set - attempting auto-detection…
    for %%P in (
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC"
    ) do (
        if exist "%%~P\Auxiliary\Build\vcvars64.bat" (
            set "VCINSTALLDIR=%%~P"
            echo Found Visual C++ Build Tools at: %%~P
            goto :vc_found
        )
    )
    echo ERROR: Could not find a suitable Visual Studio installation.
    echo        Install "Desktop development with C++" or set VCINSTALLDIR.
    exit /b 1
)
:vc_found

if "%VCINSTALLDIR:~-1%"=="\" set "VCINSTALLDIR=%VCINSTALLDIR:~0,-1%"
echo Initialising MSVC environment…
call "%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat" || (
    echo ERROR: Failed to initialise MSVC toolchain.
    exit /b 1
)

REM ── Determine a sane VCPKG_ROOT (prefer C:\vcpkg) ──────────────────────────
if "%VCPKG_ROOT%"=="" (
  for %%D in (C D E) do (
    if exist "%%D:\vcpkg\vcpkg.exe" set "VCPKG_ROOT=%%D:\vcpkg"
  )
)
if "%VCPKG_ROOT%"=="" set "VCPKG_ROOT=C:\vcpkg"

REM Normalise any inherited mismatched value
set "VCPKG_ROOT=%VCPKG_ROOT%"

REM ── Find or (re)install vcpkg ──────────────────────────────────────────────
call :ensure_vcpkg || exit /b 1
echo Using vcpkg root: "%VCPKG_ROOT%"
echo vcpkg executable: "%VCPKG_EXE%"

REM ── Ensure LOCALAPPDATA is drive-qualified for tools that use it ───────────
if /I not "%LOCALAPPDATA:~1,1%"==":" (
    echo LOCALAPPDATA does not start with a drive letter. Setting it to APPDATA.
    set "LOCALAPPDATA=%APPDATA%"
)

REM ── Install Hyperscan via vcpkg into THIS root ─────────────────────────────
echo Installing Hyperscan (%VCPKG_TRIPLET%) via vcpkg...
if not exist "%VCPKG_ROOT%" (
  echo ERROR: VCPKG_ROOT "%VCPKG_ROOT%" does not exist.
  exit /b 1
)
pushd "%VCPKG_ROOT%" || (
  echo ERROR: Cannot cd into "%VCPKG_ROOT%".
  exit /b 1
)
"%VCPKG_EXE%" --vcpkg-root "%VCPKG_ROOT%" install hyperscan:%VCPKG_TRIPLET% || (
    echo ERROR: vcpkg install failed.
    popd
    exit /b 1
)
popd

REM ── Point build to the installed Hyperscan include/lib ─────────────────────
set "LIBHS_NO_PKG_CONFIG=1"
set "HYPERSCAN_ROOT=%VCPKG_ROOT%\installed\%VCPKG_TRIPLET%"
set "HS_LIB_DIR=%HYPERSCAN_ROOT%\lib"
set "LIB=%HS_LIB_DIR%;%LIB%"
set "INCLUDE=%HYPERSCAN_ROOT%\include;%INCLUDE%"

REM Verify hs.lib presence (some ports name it hs.lib; others libhs.lib)
set "HS_LIB_FILE=%HS_LIB_DIR%\hs.lib"
if not exist "%HS_LIB_FILE%" (
  if exist "%HS_LIB_DIR%\libhs.lib" (
    set "HS_LIB_FILE=%HS_LIB_DIR%\libhs.lib"
  )
)

echo.
echo [DIAG] HYPERSCAN_ROOT = %HYPERSCAN_ROOT%
echo [DIAG] HS_LIB_DIR     = %HS_LIB_DIR%
echo [DIAG] Checking for hs library...
dir /b "%HS_LIB_DIR%\hs.lib" 2>nul
dir /b "%HS_LIB_DIR%\libhs.lib" 2>nul

if not exist "%HS_LIB_FILE%" (
  echo ERROR: Could not find hs.lib (or libhs.lib) under "%HS_LIB_DIR%".
  echo        Hyperscan did not install where expected. Check vcpkg output and triplet.
  exit /b 1
)

REM ── Ensure Rust/CMake present (CI runners already have rustup; keep fallback) ─
where rustc.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing Rust via Chocolatey...
    choco install rust-ms -y
    choco install cmake -y --installargs "ADD_CMAKE_TO_PATH=System"
    call refreshenv
) else (
    echo Rust is already installed.
)

REM ── Build (static CRT) ─────────────────────────────────────────────────────
if "%RUSTFLAGS%"=="" (
  set "RUSTFLAGS=-C target-feature=+crt-static"
) else (
  echo Keeping existing RUSTFLAGS: %RUSTFLAGS%
)

echo.
echo Building static Windows x64 binary...
cargo build --release --target x86_64-pc-windows-msvc || (
    echo Cargo build failed.
    exit /b 1
)

REM ── Package & checksums (unchanged) ────────────────────────────────────────
echo Generating CHECKSUM.txt...
powershell -Command ^
  "$hash = Get-FileHash '.\target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe' -Algorithm SHA256;" ^
  "$line = '{0}  {1}' -f $hash.Hash, (Split-Path -Leaf $hash.Path);" ^
  "Set-Content -Path '.\target\x86_64-pc-windows-msvc\release\CHECKSUM.txt' -Value $line"

if not exist "target\release" mkdir "target\release"
copy /Y "target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe" "target\release\" >nul
copy /Y "target\x86_64-pc-windows-msvc\release\CHECKSUM.txt" "target\release\CHECKSUM-windows-x64.txt" >nul

cd target\release
echo Creating archive: %PROJECT_NAME%-windows-x64.zip
if exist "%PROJECT_NAME%-windows-x64.zip" del /f /q "%PROJECT_NAME%-windows-x64.zip"
powershell -Command "Compress-Archive -Path '%PROJECT_NAME%.exe','CHECKSUM-windows-x64.txt' -DestinationPath '%PROJECT_NAME%-windows-x64.zip' -Force"

if exist "%PROJECT_NAME%-windows-x64.zip" (
    powershell -Command ^
      "$hash = Get-FileHash '.\%PROJECT_NAME%-windows-x64.zip' -Algorithm SHA256;" ^
      "$line = '{0}  {1}' -f $hash.Hash, (Split-Path -Leaf $hash.Path);" ^
      "Add-Content -Path '.\CHECKSUM-windows-x64.txt' -Value $line"
    echo Created: %PROJECT_NAME%-windows-x64.zip
) else (
    echo ERROR: Archive not created.
    exit /b 1
)

echo Archives in target\release:
dir /b *.zip 2>nul || echo None found.

goto :script_end

REM =============================================================================
REM Subroutines
REM =============================================================================
:ensure_vcpkg
REM Try PATH first
where vcpkg.exe >nul 2>nul
if %ERRORLEVEL%==0 (
    for /f "tokens=*" %%i in ('where vcpkg.exe') do (
        set "VCPKG_EXE=%%i"
        echo Found vcpkg on PATH: %VCPKG_EXE%
        exit /b 0
    )
)

REM Try the chosen VCPKG_ROOT
if exist "%VCPKG_ROOT%\vcpkg.exe" (
    set "VCPKG_EXE=%VCPKG_ROOT%\vcpkg.exe"
    echo Found vcpkg at: %VCPKG_EXE%
    exit /b 0
)

if "%FORCE_VCPKG%"=="1" (
    if exist "%VCPKG_ROOT%" (
        echo Removing existing vcpkg at: %VCPKG_ROOT%
        rmdir /s /q "%VCPKG_ROOT%"
    )
) else if exist "%VCPKG_ROOT%" (
    echo Existing vcpkg directory found at "%VCPKG_ROOT%", but vcpkg.exe was not located.
    echo Recreating the installation...
    rmdir /s /q "%VCPKG_ROOT%"
)

echo Cloning and bootstrapping vcpkg into "%VCPKG_ROOT%"...
git clone https://github.com/microsoft/vcpkg.git "%VCPKG_ROOT%" || (
    echo ERROR: Failed to clone vcpkg repository.
    exit /b 1
)
pushd "%VCPKG_ROOT%"
call .\bootstrap-vcpkg.bat || (
    popd
    echo ERROR: Failed to bootstrap vcpkg.
    exit /b 1
)
set "VCPKG_EXE=%VCPKG_ROOT%\vcpkg.exe"
popd
echo Installed vcpkg at: %VCPKG_EXE%
exit /b 0

:script_end
endlocal
exit /b 0
