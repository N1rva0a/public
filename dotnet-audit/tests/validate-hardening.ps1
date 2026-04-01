param(
    [string]$SkillRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PeerSkillRoot = "",
    [string]$SharedInterop = "",
    [string]$PeerSharedInterop = ""
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

function Assert-NotContains {
    param(
        [string]$Path,
        [string]$Needle
    )

    $raw = Get-Content -LiteralPath $Path -Raw
    if ($raw.Contains($Needle)) {
        throw "Unexpected text in $Path : $Needle"
    }
}

if (-not $PeerSkillRoot) {
    if ($SkillRoot -like "*\.claude\skills\dotnet-audit") {
        $PeerSkillRoot = "$HOME\.codex\skills\dotnet-audit"
        $SharedInterop = "$HOME\.claude\skills\_shared\security-audit-interop.md"
        $PeerSharedInterop = "$HOME\.codex\skills\_shared\security-audit-interop.md"
    }
    elseif ($SkillRoot -like "*\.codex\skills\dotnet-audit") {
        $PeerSkillRoot = "$HOME\.claude\skills\dotnet-audit"
        $SharedInterop = "$HOME\.codex\skills\_shared\security-audit-interop.md"
        $PeerSharedInterop = "$HOME\.claude\skills\_shared\security-audit-interop.md"
    }
}

$skillPath = Join-Path $SkillRoot "SKILL.md"
$nugetPath = Join-Path $SkillRoot "references\dotnet\nuget_cve_matrix.md"
$fpGatePath = Join-Path $SkillRoot "references\dotnet\fp_gate_rules.md"

Assert-Contains $skillPath "PROBABLE"
Assert-Contains $skillPath "audit outcome"
Assert-Contains $skillPath "confirmed_vulns"
Assert-Contains $skillPath "probable_review"
Assert-Contains $skillPath "hypothesis_notes"
Assert-Contains $skillPath "otherwise classify as"
Assert-Contains $skillPath "based on evidence"
Assert-Contains $skillPath "finding state:"

Assert-Contains $SharedInterop "protocol_version: triad-2026-04"
Assert-Contains $SharedInterop "probable_review"
Assert-Contains $SharedInterop "hypothesis_notes"
Assert-Contains $SharedInterop "critical|high|medium|low"

Assert-Contains $nugetPath "## Hardening Note (2026-04-01)"
Assert-Contains $nugetPath "Probable"
Assert-Contains $nugetPath "P0/P1/P2/P3"

Assert-Contains $fpGatePath "reportable"
Assert-Contains $fpGatePath "PROBABLE + HYPOTHESIS"
Assert-NotContains $fpGatePath "宁可漏报"

if ($PeerSkillRoot -and (Test-Path -LiteralPath $PeerSkillRoot)) {
    $files = Get-ChildItem -LiteralPath $SkillRoot -Recurse -File | ForEach-Object { $_.FullName.Substring($SkillRoot.Length + 1) }
    foreach ($rel in $files) {
        $left = Join-Path $SkillRoot $rel
        $right = Join-Path $PeerSkillRoot $rel
        if (-not (Test-Path -LiteralPath $right)) {
            throw "Peer skill missing file: $rel"
        }

        if ((Get-FileHash -LiteralPath $left).Hash -ne (Get-FileHash -LiteralPath $right).Hash) {
            throw "Peer skill drift detected: $rel"
        }
    }
}

if ($PeerSharedInterop -and (Test-Path -LiteralPath $PeerSharedInterop)) {
    if ((Get-FileHash -LiteralPath $SharedInterop).Hash -ne (Get-FileHash -LiteralPath $PeerSharedInterop).Hash) {
        throw "Shared interop drift detected"
    }
}

Write-Output "dotnet-audit validate-hardening.ps1: PASS"
