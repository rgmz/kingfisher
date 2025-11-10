@echo off
REM ============================================================================
REM buildwin.bat — Windows x64 release build + archive for Kingfisher
REM - Forces a single vcpkg root (C:\vcpkg) and avoids VS-integrated vcpkg
REM - Installs Hyperscan for x64-windows-static into that root
REM - Verifies hs.lib is present before building, then builds & packages
REM ============================================================================

setlocal
set "PROJECT_NAME=kingfisher"
set "FORCE_VCPKG=0"
if /I "%~1"=="-force" set "FORCE_VCPKG=1"
if "%VCPKG_TRIPLET%"=="" set "VCPKG_TRIPLET=x64-windows-static"

REM --- Ensure Windows ---
if NOT "%OS%"=="Windows_NT" (
  echo This script must be run on Windows.
  exit /b 1
)

REM --- Find MSVC / init toolchain ---
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

REM --- CRITICAL: Force our own vcpkg root (ignore VS-integrated vcpkg) ----
set "VCPKG_ROOT=C:\vcpkg"
set "VCPKG_DISABLE_METRICS=1"

REM --- Ensure LOCALAPPDATA sane for tools that use it ---
if /I not "%LOCALAPPDATA:~1,1%"==":" (
  echo LOCALAPPDATA not drive-qualified; using APPDATA instead.
  set "LOCALAPPDATA=%APPDATA%"
)

REM --- Find/Install vcpkg into C:\vcpkg ---
call :ensure_vcpkg || exit /b 1
echo Using vcpkg root: "%VCPKG_ROOT%"
echo vcpkg executable: "%VCPKG_EXE%"

REM --- Install Hyperscan into THIS root ---
echo Installing Hyperscan (%VCPKG_TRIPLET%) via vcpkg...
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

REM --- Point build to installed Hyperscan ---
set "LIBHS_NO_PKG_CONFIG=1"
set "HYPERSCAN_ROOT=%VCPKG_ROOT%\installed\%VCPKG_TRIPLET%"
set "HS_LIB_DIR=%HYPERSCAN_ROOT%\lib"
set "LIB=%HS_LIB_DIR%;%LIB%"
set "INCLUDE=%HYPERSCAN_ROOT%\include;%INCLUDE%"

REM Verify hs.lib (or libhs.lib)
set "HS_LIB_FILE=%HS_LIB_DIR%\hs.lib"
if not exist "%HS_LIB_FILE%" if exist "%HS_LIB_DIR%\libhs.lib" set "HS_LIB_FILE=%HS_LIB_DIR%\libhs.lib"

echo.
echo [DIAG] HYPERSCAN_ROOT = %HYPERSCAN_ROOT%
echo [DIAG] HS_LIB_DIR     = %HS_LIB_DIR%
dir /b "%HS_LIB_DIR%\hs.lib" 2>nul
dir /b "%HS_LIB_DIR%\libhs.lib" 2>nul

if not exist "%HS_LIB_FILE%" (
  echo ERROR: Hyperscan library not found under "%HS_LIB_DIR%".
  echo        Check that hyperscan:%VCPKG_TRIPLET% installed correctly.
  exit /b 1
)

REM --- Ensure Rust/CMake present (fallback for local runs) ---
where rustc.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo Installing Rust via Chocolatey...
  choco install rust-ms -y
  choco install cmake -y --installargs "ADD_CMAKE_TO_PATH=System"
  call refreshenv
) else (
  echo Rust is already installed.
)

REM --- Build (static CRT) ---
if "%RUSTFLAGS%"=="" (
  set "RUSTFLAGS=-C target-feature=+crt-static"
) else (
  echo Using existing RUSTFLAGS: %RUSTFLAGS%
)

echo.
echo Building static Windows x64 binary...
cargo build --release --target x86_64-pc-windows-msvc || (
  echo Cargo build failed.
  exit /b 1
)

REM --- Package & checksums ---
echo Generating CHECKSUM.txt...
powershell -Command ^
  "$h=Get-FileHash '.\target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe' -Algorithm SHA256;" ^
  "$l='{0}  {1}' -f $h.Hash,(Split-Path -Leaf $h.Path);" ^
  "Set-Content '.\target\x86_64-pc-windows-msvc\release\CHECKSUM.txt' $l"

if not exist "target\release" mkdir "target\release"
copy /Y "target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe" "target\release\" >nul
copy /Y "target\x86_64-pc-windows-msvc\release\CHECKSUM.txt" "target\release\CHECKSUM-windows-x64.txt" >nul

cd target\release
echo Creating archive: %PROJECT_NAME%-windows-x64.zip
if exist "%PROJECT_NAME%-windows-x64.zip" del /f /q "%PROJECT_NAME%-windows-x64.zip"
powershell -Command "Compress-Archive -Path '%PROJECT_NAME%.exe','CHECKSUM-windows-x64.txt' -DestinationPath '%PROJECT_NAME%-windows-x64.zip' -Force"

if exist "%PROJECT_NAME%-windows-x64.zip" (
  powershell -Command ^
    "$h=Get-FileHash '.\%PROJECT_NAME%-windows-x64.zip' -Algorithm SHA256;" ^
    "$l='{0}  {1}' -f $h.Hash,(Split-Path -Leaf $h.Path);" ^
    "Add-Content '.\CHECKSUM-windows-x64.txt' $l"
  echo Created: %PROJECT_NAME%-windows-x64.zip
) else (
  echo ERROR: Archive not created.
  exit /b 1
)

echo Archives in target\release:
dir /b *.zip 2>nul || echo None found.

goto :eof

REM ====================== helpers ============================================
:ensure_vcpkg
REM If vcpkg.exe already exists under our chosen root, use it
if exist "%VCPKG_ROOT%\vcpkg.exe" (
  set "VCPKG_EXE=%VCPKG_ROOT%\vcpkg.exe"
  echo Found vcpkg at: %VCPKG_EXE%
  exit /b 0
)

REM If on PATH (and not the VS one), still force install into C:\vcpkg
where vcpkg.exe >nul 2>nul
if %ERRORLEVEL%==0 (
  for /f "tokens=*" %%i in ('where vcpkg.exe') do (
    set "VCPKG_EXE=%%i"
  )
  echo Found vcpkg on PATH: %VCPKG_EXE%
)

REM Clone/bootstrap into our root if missing
if not exist "%VCPKG_ROOT%" mkdir "%VCPKG_ROOT%"
if "%FORCE_VCPKG%"=="1" if exist "%VCPKG_ROOT%" rmdir /s /q "%VCPKG_ROOT%" & mkdir "%VCPKG_ROOT%"

if not exist "%VCPKG_ROOT%\vcpkg.exe" (
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
) else (
  set "VCPKG_EXE=%VCPKG_ROOT%\vcpkg.exe"
)

exit /b 0
