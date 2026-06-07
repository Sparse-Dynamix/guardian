function Get-RepoRoot {
    $smokeRoot = Split-Path -Parent $PSScriptRoot
    return (Resolve-Path (Join-Path $smokeRoot "..\..")).Path
}

function Resolve-GuardianBin {
    param([string]$GuardianBin)
    if (-not $GuardianBin) {
        throw "GuardianBin is required (pass -GuardianBin from smoke-all.sh)"
    }
    if (-not (Test-Path -LiteralPath $GuardianBin)) {
        throw "guardian binary not found at $GuardianBin - run scripts/build-win-smoke.ps1 first."
    }
    return $GuardianBin
}

function Get-SmokeUrl {
    if ($env:SMOKE_URL) { return $env:SMOKE_URL }
    return "http://httpbin.org/get"
}

function Resolve-CurlIp {
    param([string]$HostName)
    try {
        $entry = [System.Net.Dns]::GetHostAddresses($HostName) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1
        if ($entry) { return $entry.ToString() }
    } catch {}
    return $null
}

function New-CaDir {
    return New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("guardian-smoke-ca-" + [guid]::NewGuid())) | Select-Object -ExpandProperty FullName
}

function Resolve-Curl {
    $cmd = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "curl.exe not found in PATH"
    }
    return $cmd.Source
}

function Resolve-Cmd {
    $cmd = Get-Command cmd.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "cmd.exe not found in PATH"
    }
    return $cmd.Source
}
