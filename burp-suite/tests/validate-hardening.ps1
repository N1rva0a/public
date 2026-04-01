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
    if ($SkillRoot -like "*\.claude\skills\burp-suite") {
        $PeerSkillRoot = "$HOME\.codex\skills\burp-suite"
        $SharedInterop = "$HOME\.claude\skills\_shared\security-audit-interop.md"
        $PeerSharedInterop = "$HOME\.codex\skills\_shared\security-audit-interop.md"
    }
    elseif ($SkillRoot -like "*\.codex\skills\burp-suite") {
        $PeerSkillRoot = "$HOME\.claude\skills\burp-suite"
        $SharedInterop = "$HOME\.codex\skills\_shared\security-audit-interop.md"
        $PeerSharedInterop = "$HOME\.claude\skills\_shared\security-audit-interop.md"
    }
}

$skillPath = Join-Path $SkillRoot "SKILL.md"
$scannerPath = Join-Path $SkillRoot "references\scanner-issue-types.md"
$sqliPath = Join-Path $SkillRoot "references\sqli-engine.md"
$llmPath = Join-Path $SkillRoot "references\llm-injection-payloads.md"
$mcpPath = Join-Path $SkillRoot "references\mcp-security-patterns.md"

Assert-Contains $skillPath "EXPLOIT_QUEUE_FINAL"
Assert-Contains $skillPath "phase 3 consumes"
Assert-Contains $skillPath "manual-review items only."
Assert-Contains $skillPath "JOINT_SESSION"

Assert-Contains $SharedInterop "protocol_version: triad-2026-04"
Assert-Contains $SharedInterop "probable_review"
Assert-Contains $SharedInterop "hypothesis_notes"
Assert-Contains $SharedInterop "burp-suite v2.4+"
Assert-Contains $SharedInterop "dotnet-audit v3.3+"

Assert-Contains $scannerPath "D1 injection family"
Assert-Contains $scannerPath "D5 file operations"
Assert-Contains $scannerPath "D6 SSRF/outbound reachability"
Assert-Contains $scannerPath "D11-D14 dynamic AI tracks"
Assert-NotContains $scannerPath "JOINT_SESSION.exploit_queue"

Assert-Contains $sqliPath "PROBABLE"
Assert-Contains $sqliPath "JOINT_SESSION.surface_map[endpoint].db_type"
Assert-Contains $sqliPath "[BACKFILL_COMPLETE]"

Assert-Contains $llmPath "## Hardening Note (2026-04-01)"
Assert-Contains $llmPath "PROBABLE"

Assert-Contains $mcpPath "P0"

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

Write-Output "burp-suite validate-hardening.ps1: PASS"
