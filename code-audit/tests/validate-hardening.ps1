param(
    [string]$SkillRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$AgentRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) "subagents"),
    [string]$ExternalAgentRoot = "$HOME\.claude\agents"
)

$ErrorActionPreference = "Stop"

function Get-Frontmatter {
    param([string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw
    if ($raw -notmatch '^(?s)---\r?\n(.*?)\r?\n---\r?\n') {
        throw "Missing frontmatter: $Path"
    }

    return $Matches[1]
}

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

$skillPath = Join-Path $SkillRoot "SKILL.md"
$readmePath = Join-Path $SkillRoot "README.md"
$readmeCnPath = Join-Path $SkillRoot "README_CN.md"
$agentPath = Join-Path $SkillRoot "agent.md"
$loadMapPath = Join-Path $SkillRoot "references\\core\\load_on_demand_map.md"
$chainRefPath = Join-Path $SkillRoot "references\\core\\chain_synthesis.md"
$chainChecklistPath = Join-Path $SkillRoot "references\\checklists\\chain_synthesis.md"
$falsePositivePath = Join-Path $SkillRoot "references\\core\\false_positive_filter.md"
$controlsEnginePath = Join-Path $SkillRoot "references\\core\\security_controls_engine.py"
$interopFixturePath = Join-Path $SkillRoot "tests\\fixtures\\interop\\triad-sample.md"
$smokeAuditPath = Join-Path $SkillRoot "tests\\smoke-audit.ps1"
$smokeFixturePath = Join-Path $SkillRoot "tests\\fixtures\\smoke-java\\src\\SmokeTestVulnApp.java"

$agentNames = @(
    "audit-intel.md",
    "module-scanner.md",
    "taint-analyst.md",
    "gadget-hunter.md",
    "patch-bypass-auditor.md",
    "vuln-reporter.md",
    "chain-synthesizer.md"
)

$agentFiles = $agentNames | ForEach-Object { Join-Path $AgentRoot $_ }
$existingExternalAgentFiles = $agentNames |
    ForEach-Object { Join-Path $ExternalAgentRoot $_ } |
    Where-Object { Test-Path -LiteralPath $_ }

$refRoot = Join-Path $SkillRoot "references"

$frontmatterPaths = @($skillPath) + $agentFiles + $existingExternalAgentFiles

foreach ($path in $frontmatterPaths) {
    $frontmatter = Get-Frontmatter $path

    foreach ($badMerge in @("description: .*model:", "description: .*readonly:", "description: .*tools:", "description: .*is_background:")) {
        if ($frontmatter -match $badMerge) {
            throw "Merged frontmatter keys in $path : $badMerge"
        }
    }
}

Assert-Contains $skillPath 'Bundled prompts in `subagents/` are the versioned authority.'
Assert-Contains $skillPath 'The `[PLAN]` gate is mode-aware'
Assert-Contains $skillPath '## Triad Interop Rules'
Assert-Contains $readmePath 'Versioned specialist prompts now live under `subagents/`.'
Assert-Contains $readmePath 'tests/smoke-audit.ps1'
Assert-Contains $readmeCnPath '`subagents/`'
Assert-Contains $readmeCnPath '`.claude/agents/`'
Assert-Contains $agentPath 'bundled `subagents/` prompts are the versioned source of truth'
Assert-Contains $agentPath 'references/core/phase2_deep_methodology.md'
Assert-Contains $loadMapPath '# Load-On-Demand Reference Map'
Assert-Contains $loadMapPath '## Subagent Hints'
Assert-Contains $loadMapPath 'references/wooyun/INDEX.md'

$modulePath = Join-Path $AgentRoot "module-scanner.md"
$intelPath = Join-Path $AgentRoot "audit-intel.md"
$patchPath = Join-Path $AgentRoot "patch-bypass-auditor.md"
$taintPath = Join-Path $AgentRoot "taint-analyst.md"
$chainPath = Join-Path $AgentRoot "chain-synthesizer.md"
$gadgetPath = Join-Path $AgentRoot "gadget-hunter.md"
$reporterPath = Join-Path $AgentRoot "vuln-reporter.md"

Assert-Contains $intelPath '## Reference Activation'
Assert-Contains $modulePath 'references/core/phase2_deep_methodology.md'
Assert-Contains $modulePath '- `D9`'
Assert-Contains $modulePath 'Coverage is a means, not the goal. Finish real call chains before widening the search.'
Assert-Contains $taintPath 'references/core/sanitizer_analysis.md'
Assert-Contains $gadgetPath 'references/checklists/deserialization_filter_bypass.md'
Assert-Contains $patchPath '[PATCH_INTEL_GATE]'
Assert-Contains $reporterPath 'references/core/verification_methodology.md'
Assert-Contains $chainPath 'FINALIZED_FINDING_INDEX'
Assert-Contains $chainPath 'Use only when every node is `CONFIRMED`.'

Assert-Contains $chainRefPath 'FINALIZED_FINDING_INDEX'
Assert-Contains $chainRefPath 'ATTACK_PATH'
Assert-Contains $chainRefPath 'CANDIDATE_CHAIN'
Assert-NotContains $chainRefPath 'CONFIRMED 和 HYPOTHESIS'
Assert-NotContains $chainRefPath '将攻击链加入 EXPLOIT_QUEUE'

Assert-Contains $chainChecklistPath 'FINALIZED_FINDING_INDEX'
Assert-Contains $chainChecklistPath 'EXPLOIT_QUEUE_FINAL'
Assert-NotContains $chainChecklistPath 'CONFIRMED/HYPOTHESIS'
Assert-NotContains $chainChecklistPath '写回 `EXPLOIT_QUEUE`'

Assert-Contains $falsePositivePath 'Heuristics are escalation hints, not verdicts.'
Assert-Contains $falsePositivePath 'Never downgrade based only on a type name, annotation, framework reputation, or helper name.'
Assert-NotContains $falsePositivePath '降级为Info'

Assert-Contains $controlsEnginePath "self.exclude_tests = exclude_tests"
Assert-Contains $controlsEnginePath "--exclude-tests"
Assert-NotContains $controlsEnginePath "'test', 'tests', '__pycache__'"

Assert-Contains $interopFixturePath '[DOTNET_HANDOFF]'
Assert-Contains $smokeAuditPath 'precision_formal_sqli=no'
Assert-Contains $smokeAuditPath 'recall_formal_sqli=yes'
Assert-Contains $smokeAuditPath 'SkipModelRun'
Assert-Contains $smokeAuditPath 'smoke-audit.ps1: PASS'
Assert-Contains $smokeFixturePath 'hardcoded-demo-key'
Assert-Contains $smokeFixturePath 'ObjectInputStream'
Assert-Contains $smokeFixturePath 'Files.readAllBytes'

foreach ($name in $agentNames) {
    $internal = Join-Path $AgentRoot $name
    $external = Join-Path $ExternalAgentRoot $name

    if (Test-Path -LiteralPath $external) {
        $internalRaw = Get-Content -LiteralPath $internal -Raw
        $externalRaw = Get-Content -LiteralPath $external -Raw
        if ($internalRaw -ne $externalRaw) {
            throw "Bundled/external agent drift detected: $name"
        }
    }
}

$routeFiles = @($skillPath, $agentPath, $loadMapPath) + $agentFiles
$routeText = ($routeFiles | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n"
$allRefs = Get-ChildItem -LiteralPath $refRoot -Recurse -File | ForEach-Object { $_.FullName.Substring($refRoot.Length + 1).Replace('\','/') }
$unrouted = $allRefs | Where-Object { -not $routeText.Contains('references/' + $_) }
if ($unrouted.Count -gt 0) {
    throw "Unrouted references remain: $($unrouted -join ', ')"
}

Write-Output 'validate-hardening.ps1: PASS'
