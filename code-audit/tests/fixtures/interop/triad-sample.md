[DOTNET_HANDOFF]
protocol_version: triad-2026-03
source_skill: code-audit v5.8
target_skill: dotnet-audit v3.1
session_mode: batch
audit_mode: deep
handoff_priority: high
project_root: C:\sample\project
dotnet_shared_context:
  framework_family: ASP.NET Core
  framework_version: 8.0
  deobfuscation_confidence: Medium
  viewstate_rce_feasible: unchecked

[HANDOFF_ACK]
protocol_version: triad-2026-03
received_from: code-audit v5.8
normalized_context_key: dotnet_shared_context
shared_context_loaded: true

[SHARED_CONTEXT_WRITEBACK]
protocol_version: triad-2026-03
source_skill: dotnet-audit v3.1
target_skill: code-audit v5.8
dotnet_findings:
  deobfuscation_confidence: Medium
  viewstate_rce_confirmed: unchecked

[DOTNET_SURFACE_FEED]
protocol_version: triad-2026-03
source_skill: burp-suite v2.2
target_skill: dotnet-audit v3.1
surface_type: VIEWSTATE
endpoint: POST /legacy.aspx

[SURFACE_FEED_ACK]
protocol_version: triad-2026-03
received_from: burp-suite v2.2
target_skill: dotnet-audit v3.1
status: PROCESSING
