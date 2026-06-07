param(
    [Parameter(Mandatory = $true)]
    [string]$GuardianBin
)

$ErrorActionPreference = "Continue"
. "$PSScriptRoot\lib\common.ps1"
. "$PSScriptRoot\lib\assert.ps1"

$GuardianBin = Resolve-GuardianBin -GuardianBin $GuardianBin
$RepoRoot = Get-RepoRoot
# Avoid UNC cwd; cmd.exe rejects it when spawned under Frida.
Set-Location $env:TEMP

$Url = Get-SmokeUrl
$Curl = Resolve-Curl
$Cmd = Resolve-Cmd
$HostName = ($Url -replace '^https?://', '').Split('/')[0]
$Ip = Resolve-CurlIp -HostName $HostName
$ResolveArgs = @()
if ($Ip) {
    if ($Url -like 'https://*') {
        $ResolveArgs = @('--resolve', "${HostName}:443:${Ip}")
    } else {
        $ResolveArgs = @('--resolve', "${HostName}:80:${Ip}")
    }
}

function Invoke-DirectCase {
    param([bool]$Silent)
    $caDir = New-CaDir
    $out = New-TemporaryFile
    $err = New-TemporaryFile
    $args = @($GuardianBin)
    if ($Silent) { $args += '--silent' }
    $args += @('--ca-dir', $caDir, '--', $Curl, '-sSf')
    $args += $ResolveArgs
    $args += $Url
    & $args[0] $args[1..($args.Length - 1)] 1> $out.FullName 2> $err.FullName
    return @{ Exit = $LASTEXITCODE; Out = $out.FullName; Err = $err.FullName }
}

function Invoke-ChildCase {
    param([bool]$Silent)
    $caDir = New-CaDir
    $out = New-TemporaryFile
    $err = New-TemporaryFile
    $resolvePart = if ($ResolveArgs.Count -gt 0) { ($ResolveArgs -join ' ') + ' ' } else { '' }
    $inner = "`"$Curl -sSf ${resolvePart}$Url`""
    $args = @($GuardianBin)
    if ($Silent) { $args += '--silent' }
    $args += @('--ca-dir', $caDir, '--', $Cmd, '/c', $inner)
    & $args[0] $args[1..($args.Length - 1)] 1> $out.FullName 2> $err.FullName
    return @{ Exit = $LASTEXITCODE; Out = $out.FullName; Err = $err.FullName }
}

$casesPath = Join-Path $RepoRoot "scripts\smoke\cases.toml"
$casesToml = Get-Content -Raw -LiteralPath $casesPath
# Minimal TOML parse for our fixed schema (avoid external deps on Windows host).
$blocks = [regex]::Matches($casesToml, '(?s)\[\[case\]\](.*?)(?=\[\[case\]\]|$)')
foreach ($block in $blocks) {
    $body = $block.Groups[1].Value
    $name = if ($body -match 'name\s*=\s*"([^"]+)"') { $Matches[1] } else { continue }
    $command = if ($body -match 'command\s*=\s*"([^"]+)"') { $Matches[1] } else { 'direct' }
    $silent = ($body -match 'silent\s*=\s*true')
    $expectExit = if ($body -match 'expect_exit\s*=\s*(\d+)') { [int]$Matches[1] } else { 0 }
    $expectType = if ($body -match 'expect_jsonl_type\s*=\s*"([^"]*)"') { $Matches[1] } else { '' }

    Write-Host "==> smoke case: $name"
    $result = if ($command -eq 'child') { Invoke-ChildCase -Silent $silent } else { Invoke-DirectCase -Silent $silent }
    Assert-Exit -Expected $expectExit -Actual $result.Exit
    Assert-StdoutNonempty -Path $result.Out
    Assert-StderrJsonlType -Path $result.Err -Type $expectType
    Write-Host "    ok"
}

Write-Host "All smoke cases passed."
