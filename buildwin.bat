@echo off
REM ---------------------------------------------------------------------------
REM  Build a Windows‑x64 release binary and package it with checksums.
REM  ‑ Clones vcpkg (if requested) and pins it to commit 4887ad6d14.
REM ---------------------------------------------------------------------------

setlocal

set "PROJECT_NAME=kingfisher"
set "VCPKG_COMMIT=4887ad6d14"     REM ← known‑good vcpkg snapshot

REM ── Require Windows ────────────────────────────────────────────────────────
if NOT "%OS%"=="Windows_NT" (
    echo This script must be run on Windows.
    exit /b 1
)

REM ── Locate MSVC toolchain ──────────────────────────────────────────────────
if "%VCINSTALLDIR%"=="" (
    echo VCINSTALLDIR not set - attempting auto-detection…
    for %%P in (
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC"
    ) do if exist "%%~P\Auxiliary\Build\vcvars64.bat" (
        set "VCINSTALLDIR=%%~P"
        echo Found Visual C++ Build Tools at: %%~P
        goto :vc_found
    )
    echo ERROR: Could not find a suitable Visual Studio installation.
    exit /b 1
)
:vc_found
if "%VCINSTALLDIR:~-1%"=="\" set "VCINSTALLDIR=%VCINSTALLDIR:~0,-1%"

echo Initialising MSVC environment…
call "%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat" || (
    echo ERROR: Failed to initialise MSVC toolchain.
    exit /b 1
)

REM ── Locate or bootstrap vcpkg, then pin to commit ──────────────────────────
where vcpkg.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    REM ----- vcpkg.exe not on PATH ------------------------------------------
    if exist "%HOMEDRIVE%\vcpkg\vcpkg.exe" (
        REM vcpkg folder exists → pin it
        echo Found existing vcpkg tree, pinning to %VCPKG_COMMIT%…
        git -C "%HOMEDRIVE%\vcpkg" fetch --depth=1 origin %VCPKG_COMMIT%
        git -C "%HOMEDRIVE%\vcpkg" checkout %VCPKG_COMMIT% ^
            || (echo ERROR: checkout failed.&exit /b 1)
    ) else if "%~1"=="-force" (
        REM Fresh clone
        echo Cloning and bootstrapping vcpkg at commit %VCPKG_COMMIT%…
        if exist "%HOMEDRIVE%\vcpkg" rmdir /s /q "%HOMEDRIVE%\vcpkg"
        git clone https://github.com/microsoft/vcpkg.git "%HOMEDRIVE%\vcpkg" ^
            || (echo ERROR: git clone failed.&exit /b 1)
        pushd "%HOMEDRIVE%\vcpkg"
        git checkout %VCPKG_COMMIT% || (echo ERROR: checkout failed.&exit /b 1)
        call .\bootstrap-vcpkg.bat  || (echo ERROR: bootstrap failed.&exit /b 1)
        popd
    ) else (
        echo ERROR: vcpkg not found. Install it or rerun with -force.
        exit /b 1
    )
) else (
    REM ----- vcpkg.exe already on PATH ---------------------------------------
    for /f "tokens=*" %%i in ('where vcpkg.exe') do set "VCPKG_EXE=%%i"
    echo Found vcpkg at: %VCPKG_EXE%
    REM Ensure the tree is on the expected commit
    git -C "%HOMEDRIVE%\vcpkg" fetch --depth=1 origin %VCPKG_COMMIT%
    git -C "%HOMEDRIVE%\vcpkg" checkout %VCPKG_COMMIT% ^
        || (echo ERROR: checkout failed.&exit /b 1)
)
if not defined VCPKG_EXE set "VCPKG_EXE=%HOMEDRIVE%\vcpkg\vcpkg.exe"

REM ── LOCALAPPDATA fix for CI ------------------------------------------------
if /I not "%LOCALAPPDATA:~1,1%"==":" (
    echo LOCALAPPDATA lacks drive letter; pointing it at APPDATA.
    set "LOCALAPPDATA=%APPDATA%"
)

REM ── Install Hyperscan (unchanged) -----------------------------------------
echo Installing hyperscan via vcpkg...
"%VCPKG_EXE%" install hyperscan:x64-windows
set "LIBHS_NO_PKG_CONFIG=1"
set "HYPERSCAN_ROOT=%HOMEDRIVE%\vcpkg\installed\x64-windows"
set "LIB=%HYPERSCAN_ROOT%\lib;%LIB%"
set "INCLUDE=%HYPERSCAN_ROOT%\include;%INCLUDE%"

REM ── Check for Rust toolchain (unchanged) -----------------------------------
where rustc.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Rust...
    choco install rust-ms -y
    choco install cmake -y --installargs "ADD_CMAKE_TO_PATH=System"
    call refreshenv
) else (
    echo Rust is already installed.
)

REM ── Build (unchanged) ------------------------------------------------------
echo Building for Windows x64...
cargo build --release --target x86_64-pc-windows-msvc || (
    echo Cargo build failed.
    exit /b 1
)

REM ── Package & checksum (unchanged) ----------------------------------------
echo Generating CHECKSUM.txt...
powershell -Command ^
  "Get-FileHash .\target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe -Algorithm SHA256 | Out-File .\target\x86_64-pc-windows-msvc\release\CHECKSUM.txt"

if not exist "target\release" mkdir "target\release"
copy /Y "target\x86_64-pc-windows-msvc\release\%PROJECT_NAME%.exe" "target\release\" >nul
copy /Y "target\x86_64-pc-windows-msvc\release\CHECKSUM.txt" "target\release\CHECKSUM-windows-x64.txt" >nul

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
