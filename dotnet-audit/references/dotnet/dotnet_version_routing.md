# .NET 框架版本分支路由

> Phase 0 侦察完成后立即执行本路由。根据目标框架类型和版本，激活/禁用特定审计模块，
> 避免对不适用攻击面产生误报，同时确保版本专属漏洞不被遗漏。

---

## 路由决策树

```
Phase 0 [RECON] 框架字段
         ↓
    ┌────────────────────────────────────────────┐
    │  .NET Framework（Classic ASP.NET）          │
    │  特征: targetFramework="net4x" / net35 /    │
    │        net20；Web.config 存在；             │
    │        using System.Web.Mvc                 │
    └─────────────────────────┬──────────────────┘
                              ↓
              ┌───────────────┴───────────────┐
          ≤ 4.5.1                         ≥ 4.5.2
              ↓                               ↓
      激活: ViewState/MachineKey          激活: ViewState/MachineKey
      激活: BinaryFormatter               激活: BinaryFormatter（但需检查
      激活: XmlDocument XXE               EnableUnsafeBinary开关）
      激活: ActivitySurrogateSelector     激活: Json.NET TypeNameHandling
      激活: .NET Remoting（若存在）        禁用: ActivitySurrogateSelector
      激活: LosFormatter                  激活: LosFormatter
      激活: NDCS/LosFormatter             XXE: 检查 XmlResolver 配置

    .NET 5 / 6 / 7 / 8（ASP.NET Core）
    特征: <TargetFramework>net6.0</TargetFramework>
          Program.cs 无 System.Web；appsettings.json
          ↓
    禁用: ViewState / MachineKey（WebForms 不存在）
    禁用: BinaryFormatter（默认抛异常，但检查 EnableUnsafeBinary 开关）
    禁用: ActivitySurrogateSelector（已修复）
    禁用: .NET Remoting（已废弃）
    禁用: LosFormatter（已废弃）
    激活: Json.NET TypeNameHandling（若使用 Json.NET）
    激活: System.Text.Json（检查 JsonSerializerOptions.PropertyNameCaseInsensitive 等）
    激活: Blazor Server（见 blazor_signalr_security.md）
    激活: SignalR（见 blazor_signalr_security.md）
    激活: gRPC（若存在）
    激活: JWT / OIDC（ASP.NET Core Identity / Microsoft.Identity.Web）
    激活: CORS 策略审计（AddCors/WithOrigins）
    激活: HSTS / HTTPS Redirection
    激活: AntiForgery（AddAntiforgery / ValidateAntiForgeryToken）

    ASP.NET Core 1.x / 2.x（老旧）
    特征: <PackageReference Include="Microsoft.AspNetCore" Version="1/2.*" />
          ↓
    激活以上 .NET 5+ 所有项
    额外激活: CVE-2019-0613（代码注入，ASP.NET MVC < 5.2.7）
    额外激活: AntiForgery bypass（Core 2.x 已知绕过）
    额外激活: JWT validation gap（Microsoft.IdentityModel.Tokens < 5.x）

    WCF（Windows Communication Foundation）
    特征: System.ServiceModel / serviceModel in Web.config
          ↓
    激活: wcf_security.md（TypeFilterLevel.Full, 元数据暴露, 传输安全）
    激活: NetDataContractSerializer（直接 Confirmed）
    激活: BinaryFormatter（通过 WCF NetTcpBinding）
    激活: 消息重放攻击

    WinForms / WPF（桌面应用）
    特征: Application.Run(new Form()) / App.xaml
          ↓
    激活: BinaryFormatter（桌面场景常见）
    激活: ClickOnce 部署安全
    激活: TextFormattingRunProperties gadget（WPF 专属）
    激活: DLL 劫持（应用程序目录加载）
    注意: 无 HTTP 端点 → EXPLOIT_QUEUE 中标注 [非HTTP协议]
```

---

## 版本专属 CVE 快查

| 框架版本 | 典型高危 CVE | 严重性 |
|---------|------------|--------|
| .NET Framework ≤ 4.5.1 | CVE-2011-1203（XmlDocument XXE）| Critical |
| ASP.NET MVC ≤ 5.2.6 | CVE-2019-0613（代码注入）| High |
| ASP.NET Core ≤ 2.1 | CVE-2019-0564（DoS）| Medium |
| ASP.NET Core ≤ 2.2 | CVE-2019-0981（路径遍历）| High |
| .NET Framework 所有 | CVE-2023-36434（MachineKey 信息泄露）| High |
| System.Text.Encodings.Web < 4.5.1 | CVE-2021-26701（ReDoS）| Medium |
| Microsoft.AspNetCore.Http < 2.2.8 | CVE-2019-1075（开放重定向）| Medium |

---

## 路由结论输出格式（Phase 0 末尾输出）

```
[VERSION_ROUTING]
框架类型: {.NET Framework X.Y / ASP.NET Core X.Y / WCF / WinForms/WPF}
路由分支: {Framework-Classic / Core-Modern / WCF / Desktop}

激活模块:
  ✅ BinaryFormatter 反序列化审计
  ✅ ViewState/MachineKey RCE（见 viewstate_machinekey.md）
  ✅ ysoserial.net gadget 链（见 ysoserial_net.md）
  ✅ Json.NET TypeNameHandling
  ✅ JWT/OIDC 认证审计
  ...

禁用模块（避免误报）:
  ❌ ViewState/MachineKey（ASP.NET Core 无 WebForms）
  ❌ BinaryFormatter（.NET 7+ 默认禁用，已确认无 EnableUnsafeBinary 开关）
  ❌ ActivitySurrogateSelector（.NET 4.7+ 已修复）
  ...

版本专属 CVE 候选:
  {匹配当前版本的 CVE 列表，空则"无已知版本专属CVE"}
```

---

## 误报防护规则

```
规则A: 报告 BinaryFormatter 漏洞前，必须确认：
  .NET Framework → 直接 Confirmed
  .NET 5/6 → 先 grep EnableUnsafeBinaryFormatterSerialization
             若未找到或值为 false → FP（运行时阻断）
             若值为 true → Confirmed

规则B: 报告 ViewState RCE 前，必须确认：
  项目类型为 ASP.NET WebForms（存在 .aspx 文件 + System.Web）
  ASP.NET Core 项目 → FP（ViewState 不存在）

规则C: 报告 ActivitySurrogateSelector gadget 前，必须确认：
  目标 .NET Framework 版本 < 4.7
  ≥ 4.7 → FP（已添加运行时检查）

规则D: 报告 XmlDocument XXE 前，必须确认：
  .NET ≤ 4.5.1 → 检查是否有 XmlResolver = null 显式设置
  .NET ≥ 4.5.2 → 默认 XmlResolver = null，必须检查是否被显式设回 XmlUrlResolver
```
