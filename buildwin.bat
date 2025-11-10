@echo off
REM This script builds a Windows x64 release binary and creates a tarball with checksum.
REM It requires vcpkg to be installed at root of C: drive (https://github.com/microsoft/vcpkg).
REM This script will install Rust (using chocolatey) if it is not already installed.
REM
REM Call with -force to clone and bootstrap vcpkg if it is not found
REM

setlocal

REM Set your Cargo project name manually here if desired:
set "PROJECT_NAME=kingfisher"
set "VCPKG_ROOT=%HOMEDRIVE%\vcpkg"
set "FORCE_VCPKG=0"
if /I "%~1"=="-force" set "FORCE_VCPKG=1"

REM Optional check for OS:
if NOT "%OS%"=="Windows_NT" (
    echo This script must be run on Windows.
    exit /b 1
)
if "%VCINSTALLDIR%"=="" (
    echo VCINSTALLDIR not set - attempting auto-detection…
    for %%P in (
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC"
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
    echo        Install “Desktop development with C++” or set VCINSTALLDIR.
    exit /b 1
)
:vc_found

REM Strip trailing backslash if present
if "%VCINSTALLDIR:~-1%"=="\" set "VCINSTALLDIR=%VCINSTALLDIR:~0,-1%"

echo Initialising MSVC environment…
call "%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat" || (
    echo ERROR: Failed to initialise MSVC toolchain.
    exit /b 1
)

REM Locate (or install) vcpkg.exe
call :ensure_vcpkg || exit /b 1

REM Check if LOCALAPPDATA starts with a drive letter, if not set it to APPDATA
if /I not "%LOCALAPPDATA:~1,1%"==":" (
    echo LOCALAPPDATA does not start with a drive letter. Setting it to APPDATA.
    set "LOCALAPPDATA=%APPDATA%"
)

REM ── Install Hyperscan ------------------------------------------------------
set "VCPKG_TRIPLET=x64-windows-static"
echo Installing Hyperscan (%VCPKG_TRIPLET%) via vcpkg...
pushd "%VCPKG_ROOT%"           REM ► work inside the vcpkg root
"%VCPKG_EXE%" install hyperscan:%VCPKG_TRIPLET% || (
    echo ERROR: vcpkg install failed.
    popd
    exit /b 1
)
popd
set "LIBHS_NO_PKG_CONFIG=1"

REM Point vectorscan‑rs‑sys at the Hyperscan install
set "HYPERSCAN_ROOT=%VCPKG_ROOT%\installed\%VCPKG_TRIPLET%"
set "LIB=%HYPERSCAN_ROOT%\lib;%LIB%"
set "INCLUDE=%HYPERSCAN_ROOT%\include;%INCLUDE%"

REM Check for Rust, install if missing
where rustc.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing Rust...
    choco install rust-ms -y
    choco install cmake -y --installargs "ADD_CMAKE_TO_PATH=System"
    call refreshenv

) else (
    echo Rust is already installed.
)

set "RUSTFLAGS=%RUSTFLAGS% -C target-feature=+crt-static"

echo Building static Windows x64 binary...
cargo build --release --target x86_64-pc-windows-msvc || (
    echo Cargo build failed.
    exit /b 1
)

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
    REM -- append the ZIP’s SHA-256 to the existing checksum file ----
    powershell -Command ^
      "$hash = Get-FileHash '.\%PROJECT_NAME%-windows-x64.zip' -Algorithm SHA256;" ^
      "$line = '{0}  {1}' -f $hash.Hash, (Split-Path -Leaf $hash.Path);" ^
      "Add-Content -Path '.\CHECKSUM-windows-x64.txt' -Value $line"
    echo Created: %PROJECT_NAME%-windows-x64.zip
) else (
    echo ERROR: Archive not created.
)

echo Archives in target\release:
dir /b *.zip 2>nul || echo None found.

goto :script_end

:ensure_vcpkg
where vcpkg.exe >nul 2>nul
if %ERRORLEVEL%==0 (
    for /f "tokens=*" %%i in ('where vcpkg.exe') do (
        set "VCPKG_EXE=%%i"
        echo Found vcpkg at: %VCPKG_EXE%
        exit /b 0
    )
)

if "%FORCE_VCPKG%"=="0" if exist "%VCPKG_ROOT%\vcpkg.exe" (
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
    echo Existing vcpkg directory found at %VCPKG_ROOT%, but vcpkg.exe was not located.
    echo Recreating the installation...
    rmdir /s /q "%VCPKG_ROOT%"
)

echo Cloning and bootstrapping vcpkg into %VCPKG_ROOT%...
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
