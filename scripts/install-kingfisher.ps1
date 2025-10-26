<#
.SYNOPSIS
    Download and install the latest Kingfisher release for Windows.

.DESCRIPTION
    Fetches the most recent GitHub release for mongodb/kingfisher, downloads the
    Windows x64 archive, and extracts kingfisher.exe to the destination folder.
    By default the script installs into "$env:USERPROFILE\bin".

.PARAMETER InstallDir
    Optional destination directory for the kingfisher.exe binary.

.EXAMPLE
    ./install-kingfisher.ps1

.EXAMPLE
    ./install-kingfisher.ps1 -InstallDir "C:\\Tools"
#>
param(
    [Parameter(Position = 0)]
    [string]$InstallDir = (Join-Path $env:USERPROFILE 'bin')
)

$repo = 'mongodb/kingfisher'
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"
$assetName = 'kingfisher-windows-x64.zip'

if (-not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    throw 'Invoke-WebRequest is required to download releases.'
}

if (-not (Get-Command Expand-Archive -ErrorAction SilentlyContinue)) {
    throw 'Expand-Archive is required to extract the release archive. Install the PowerShell archive module.'
}

Write-Host "Fetching latest release metadata for $repo…"
try {
    $response = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing
    $release = $response.Content | ConvertFrom-Json
} catch {
    throw "Failed to retrieve release information from GitHub: $_"
}

$releaseTag = $release.tag_name
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    throw "Could not find asset '$assetName' in the latest release."
}

$tempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ([System.Guid]::NewGuid().ToString())
$archivePath = Join-Path $tempDir.FullName $assetName

try {
    if ($releaseTag) {
        Write-Host "Latest release: $releaseTag"
    }

    Write-Host "Downloading $assetName…"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -UseBasicParsing

    Write-Host 'Extracting archive…'
    Expand-Archive -Path $archivePath -DestinationPath $tempDir.FullName -Force

    $binaryPath = Join-Path $tempDir.FullName 'kingfisher.exe'
    if (-not (Test-Path $binaryPath)) {
        throw 'Extracted archive did not contain kingfisher.exe.'
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $destination = Join-Path $InstallDir 'kingfisher.exe'
    Copy-Item -Path $binaryPath -Destination $destination -Force

    Write-Host "Kingfisher installed to: $destination"
    Write-Host "Ensure '$InstallDir' is in your PATH environment variable."
}
finally {
    if ($tempDir -and (Test-Path $tempDir.FullName)) {
        Remove-Item -Path $tempDir.FullName -Recurse -Force
    }
}
