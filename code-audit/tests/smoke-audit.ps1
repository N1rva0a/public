param(
    [string]$SkillRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipModelRun,
    [string]$ClaudeExe = "claude.exe"
)

$ErrorActionPreference = "Stop"

function Assert-Contains {
    param(
        [string]$Path,
        [string]$Needle
    )

    $raw = Get-Content -LiteralPath $Path -Raw
    if (-not $raw.Contains($Needle)) {
        throw "Missing required text in $Path : $Needle"
    }
}

function Invoke-ClaudeCheck {
    param(
        [string]$Prompt,
        [string]$ExpectedLine
    )

    $output = & $ClaudeExe --bare -p $Prompt --allowedTools Read,Glob,Grep,Bash --dangerously-skip-permissions 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Claude CLI smoke failed: $output"
    }

    if ($output -match 'Cursor support assistant') {
        throw "Claude CLI did not load the intended audit skill context."
    }

    if ($output -notmatch "(?m)^$([regex]::Escape($ExpectedLine))$") {
        throw "Unexpected semantic smoke output. Expected '$ExpectedLine' but got:`n$output"
    }
}

$precision = Join-Path $SkillRoot "tests\fixtures\precision-java\src\SafeSearchController.java"
$recall = Join-Path $SkillRoot "tests\fixtures\recall-java\src\VulnerableUserController.java"
$smoke = Join-Path $SkillRoot "tests\fixtures\smoke-java\src\SmokeTestVulnApp.java"

Assert-Contains $precision 'PreparedStatement'
Assert-Contains $precision 'setString'
Assert-Contains $precision 'enum SortField'

Assert-Contains $recall 'createStatement'
Assert-Contains $recall '" + username + "'
Assert-Contains $recall 'executeQuery'

Assert-Contains $smoke 'hardcoded-demo-key'
Assert-Contains $smoke 'createStatement'
Assert-Contains $smoke 'Files.readAllBytes'
Assert-Contains $smoke 'ObjectInputStream'
Assert-Contains $smoke 'adminRun'

if (-not $SkipModelRun) {
    if (-not (Get-Command $ClaudeExe -ErrorAction SilentlyContinue)) {
        throw "Claude CLI not found. Install it or run smoke-audit.ps1 -SkipModelRun for offline static-only checks."
    }

    Push-Location $SkillRoot
    try {
        Invoke-ClaudeCheck -Prompt @"
Run /audit in quick mode using the code-audit skill in this repository.
Audit ONLY the fixture file `tests/fixtures/precision-java/src/SafeSearchController.java`.
Determine whether there is a formal SQL injection.
Reply with exactly one line:
precision_formal_sqli=no
"@ -ExpectedLine 'precision_formal_sqli=no'

        Invoke-ClaudeCheck -Prompt @"
Run /audit in quick mode using the code-audit skill in this repository.
Audit ONLY the fixture file `tests/fixtures/recall-java/src/VulnerableUserController.java`.
Determine whether there is a formal SQL injection.
Reply with exactly one line:
recall_formal_sqli=yes
"@ -ExpectedLine 'recall_formal_sqli=yes'
    }
    finally {
        Pop-Location
    }
}

Write-Output 'smoke-audit.ps1: PASS'
