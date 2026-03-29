param(
    [string]$Repo = $(if ($env:SAPBLOB_REPO) { $env:SAPBLOB_REPO } else { "umsername/sap-blob-decompress" }),
    [string]$Version = $(if ($env:SAPBLOB_VERSION) { $env:SAPBLOB_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:SAPBLOB_INSTALL_DIR) { $env:SAPBLOB_INSTALL_DIR } else { "$HOME\bin" })
)

$ErrorActionPreference = 'Stop'

function Get-GoArch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

    switch ($arch) {
        'X64'   { return 'amd64' }
        'Arm64' { return 'arm64' }
        default { throw "Unsupported Windows architecture: $arch" }
    }
}

function Resolve-Version {
    param(
        [string]$Repository,
        [string]$RequestedVersion
    )

    if ($RequestedVersion -ne 'latest') {
        return $RequestedVersion
    }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest"

    if (-not $release.tag_name) {
        throw 'Could not determine the latest release tag.'
    }

    return $release.tag_name
}

function Install-Release {
    param(
        [string]$Repository,
        [string]$ResolvedVersion,
        [string]$TargetDirectory,
        [string]$GoArch
    )

    $binName = 'sapblob.exe'
    $archiveName = "sapblob_${ResolvedVersion}_windows-${GoArch}.zip"
    $downloadUrl = "https://github.com/$Repository/releases/download/$ResolvedVersion/$archiveName"
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())

    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        $archivePath = Join-Path $tempDir $archiveName

        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
        Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force

        $binary = Get-ChildItem -Path $tempDir -Recurse -Filter $binName | Select-Object -First 1
        if (-not $binary) {
            throw 'Release archive did not contain sapblob.exe.'
        }

        New-Item -ItemType Directory -Force -Path $TargetDirectory | Out-Null
        Copy-Item $binary.FullName (Join-Path $TargetDirectory $binName) -Force

        Write-Host "Installed $binName $ResolvedVersion to $(Join-Path $TargetDirectory $binName)"
    }
    finally {
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }
}

$goArch = Get-GoArch
$resolvedVersion = Resolve-Version -Repository $Repo -RequestedVersion $Version
Install-Release -Repository $Repo -ResolvedVersion $resolvedVersion -TargetDirectory $InstallDir -GoArch $goArch
