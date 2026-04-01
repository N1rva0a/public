param(
    [string]$SkillRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$BurpSkill = "$HOME\.codex\skills\burp-suite\SKILL.md",
    [string]$DotnetSkill = "$HOME\.codex\skills\dotnet-audit\SKILL.md",
    [string]$SharedInterop = "$HOME\.codex\skills\_shared\security-audit-interop.md"
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

$skillPath = Join-Path $SkillRoot "SKILL.md"
$agentPath = Join-Path $SkillRoot "agent.md"
$fixturePath = Join-Path $SkillRoot "tests\fixtures\interop\triad-sample.md"

Assert-Contains $SharedInterop '[DOTNET_HANDOFF]'
Assert-Contains $SharedInterop '[HANDOFF_ACK]'
Assert-Contains $SharedInterop '[SHARED_CONTEXT_WRITEBACK]'
Assert-Contains $SharedInterop '[DOTNET_SURFACE_FEED]'
Assert-Contains $SharedInterop '[SURFACE_FEED_ACK]'
Assert-Contains $SharedInterop 'dotnet_shared_context'
Assert-Contains $SharedInterop 'JOINT_SESSION'

Assert-Contains $skillPath '## Triad Interop Rules'
Assert-Contains $skillPath '../_shared/security-audit-interop.md'
Assert-Contains $skillPath '[DOTNET_HANDOFF]'
Assert-Contains $skillPath '[SHARED_CONTEXT_WRITEBACK]'
Assert-Contains $skillPath '[DOTNET_SURFACE_FEED]'

Assert-Contains $agentPath '## Triad Dispatch Rules'
Assert-Contains $agentPath '[DOTNET_HANDOFF]'
Assert-Contains $agentPath '[HANDOFF_ACK]'
Assert-Contains $agentPath '[SHARED_CONTEXT_WRITEBACK]'
Assert-Contains $agentPath '[DOTNET_SURFACE_FEED]'
Assert-Contains $agentPath '[SURFACE_FEED_ACK]'
Assert-Contains $agentPath 'JOINT_SESSION'

Assert-Contains $BurpSkill '[DOTNET_SURFACE_FEED]'
Assert-Contains $BurpSkill 'JOINT_SESSION'
Assert-Contains $DotnetSkill '[DOTNET_HANDOFF]'
Assert-Contains $DotnetSkill '[HANDOFF_ACK]'
Assert-Contains $DotnetSkill '[SHARED_CONTEXT_WRITEBACK]'
Assert-Contains $DotnetSkill '[DOTNET_SURFACE_FEED]'
Assert-Contains $DotnetSkill '[SURFACE_FEED_ACK]'

Assert-Contains $fixturePath '[DOTNET_HANDOFF]'
Assert-Contains $fixturePath '[HANDOFF_ACK]'
Assert-Contains $fixturePath '[SHARED_CONTEXT_WRITEBACK]'
Assert-Contains $fixturePath '[DOTNET_SURFACE_FEED]'
Assert-Contains $fixturePath '[SURFACE_FEED_ACK]'
Assert-Contains $fixturePath 'dotnet_shared_context'

Write-Output 'smoke-interop.ps1: PASS'
