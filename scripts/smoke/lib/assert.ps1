function Assert-Exit {
    param([int]$Expected, [int]$Actual)
    if ($Actual -ne $Expected) {
        throw "ASSERT exit: expected $Expected, got $Actual"
    }
}

function Assert-StdoutNonempty {
    param([string]$Path)
    if (-not (Test-Path $Path) -or (Get-Item $Path).Length -eq 0) {
        throw "ASSERT stdout: expected non-empty output"
    }
}

function Assert-StderrJsonlType {
    param([string]$Path, [string]$Type)
    $text = if (Test-Path $Path) { Get-Content -Raw -LiteralPath $Path } else { "" }
    if (-not $Type) {
        if ($text -match '(?m)^\s*\{') {
            throw "ASSERT stderr: expected no JSONL, found JSON lines"
        }
        return
    }
    if ($text -notmatch '"type"\s*:\s*"' + [regex]::Escape($Type) + '"') {
        throw "ASSERT stderr: expected JSONL type $Type`n--- stderr ---`n$text"
    }
}
