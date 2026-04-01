# NuGet 包 CVE 情报矩阵

> Phase 0S 供应链审计核心数据源。每次审计前使用本矩阵比对目标项目依赖，
> 命中即触发 Layer 2 深度验证。本文件持续维护，按风险等级排序。
>
> **使用方式**: Phase 0S 扫描出依赖列表后，与下方矩阵逐条比对。
> 版本范围命中 → `[CoT思考链] NuGet漏洞` → 成立条件判断 → 入队或FP。

---

## Hardening Note (2026-04-01)

- 本文件中的 `P0/P1/P2/P3` 仅表示修复排期优先级，不是 lifecycle 状态。
- 版本命中但调用链未闭合时，优先使用 `PROBABLE`，而不是把所有未完全证实项压成 `HYPOTHESIS`。

## 成立条件通用框架

```
[CoT思考链] NuGet漏洞: {包名@版本}
① 观察: 项目实际版本 {X.Y.Z}，CVE影响范围 {≤A.B.C}
② 假设:
   A) 版本在影响范围内，漏洞API被调用且输入/控制面可达 → Confirmed
   B) 版本在范围内，危险能力相关但调用链或运行时条件未闭合 → Probable
   C) 版本在范围内，但证据很弱或仅有名称命中 → Hypothesis
   D) 版本已修复 → FP
③ 排除: 确认实际版本号（packages.config / .csproj PackageReference）
④ 验证: grep 漏洞触发API是否在项目中调用 + 输入是否可控
⑤ 结论: {Confirmed / Probable / Hypothesis / FP}

成立标准:
✅ Confirmed: 版本命中 + 漏洞API被调用 + 输入路径可控
🔍 Probable: 版本命中 + 危险能力相关 + 调用路径或配置条件仍需补证
🔍 Hypothesis: 版本命中 + 调用路径不明确 或 仅有弱相关信号
❌ FP: 版本已修复 / 漏洞API未使用 / 触发需特殊配置但目标未启用
```

---

## Critical 级 CVE（必须入 EXPLOIT_QUEUE）

### Newtonsoft.Json（Json.NET）

| CVE / GHSA | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----------|---------|---------|------------|
| CVE-2024-21907 | < 13.0.1 | ReDoS（正则指数回溯） | 6 |
| 历史: TypeNameHandling | 任意版本（配置触发）| 反序列化RCE | 10 |

**CVE-2024-21907 成立条件**:
```csharp
// 触发: 解析攻击者可控的超长日期字符串
JsonConvert.DeserializeObject(userInput);  // 无类型限定时
// 成立: 有公开HTTP接口接受JSON body + 无请求大小限制
// FP: 仅内部可信数据源 / 请求体大小有硬限制
```

**TypeNameHandling 成立条件**:
```csharp
// 直接Confirmed:
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All   // ← 高危
});
// 直接Confirmed:
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Auto  // ← 高危（含$type字段时触发）
});
// FP:
JsonConvert.DeserializeObject<MyClass>(json);  // 强类型，不触发
```

---

### Microsoft.Data.SqlClient / System.Data.SqlClient

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2024-0056 | Microsoft.Data.SqlClient < 5.1.3 / < 2.0.0 | MitM证书注入，可篡改SQL | 8 |
| CVE-2022-41064 | System.Data.SqlClient（所有.NET Fx版本）| 信息泄露 | 5 |

**CVE-2024-0056 成立条件**:
```
成立: 目标系统部署在可被攻击者控制网络路径的环境 + 未强制TLS证书校验
FP: 内网隔离环境 / 数据库连接字符串含 Encrypt=True;TrustServerCertificate=False
```

---

### Microsoft.AspNetCore.Authentication.JwtBearer

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2024-21386 | < 6.0.26, < 7.0.15, < 8.0.2 | DoS（恶意JWT触发异常）| 5 |
| CVE-2021-34532 | < 5.0.8 | JWT密钥信息泄露（日志记录）| 6 |

**CVE-2021-34532 成立条件**:
```bash
# 检测: 应用是否启用详细日志 + 日志是否可被攻击者读取
grep -rn "LogLevel.*Debug\|LogLevel.*Trace" --include="appsettings*.json" . 2>/dev/null
grep -rn "AddConsole\|AddDebug" --include="*.cs" . | grep "Logging" 2>/dev/null
# 成立: 日志级别为Debug/Trace + 日志写入可访问位置（文件/ElasticSearch）
```

---

### ImageSharp（SixLabors.ImageSharp）

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2024-27929 | < 3.1.4 | 内存耗尽DoS（恶意图片）| 5 |
| CVE-2023-4508 | < 2.1.4 | CPU耗尽DoS | 5 |

**成立条件**:
```csharp
// 触发: 处理用户上传的图片
using var image = await Image.LoadAsync(userUploadStream);  // 无大小/格式预检
// 成立: 存在文件上传功能 + 使用ImageSharp处理 + 无文件大小限制
// FP: 上传前有文件大小硬限制（< 10MB）且格式白名单验证
```

---

### DotNetZip（Ionic.Zip）

| CVE / GHSA | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----------|---------|---------|------------|
| GHSA-gqqm-fg8v-58rr | 所有版本（已停更） | ZipSlip路径遍历 → 任意文件写入 | 8 |

> ⚠️ DotNetZip 已停止维护，任何版本均存在风险，建议迁移至 System.IO.Compression。

**ZipSlip 成立条件**:
```csharp
// 高危模式: 未验证ZipEntry路径
foreach (ZipEntry entry in zip.Entries) {
    entry.Extract(outputDir);  // entry.FileName 可能含 ../../
}
// 安全模式（不报告）:
string safePath = Path.GetFullPath(Path.Combine(outputDir, entry.FileName));
if (!safePath.StartsWith(outputDir)) throw new Exception("ZipSlip detected");
```

---

### SharpZipLib（ICSharpCode.SharpZipLib）

| CVE / GHSA | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----------|---------|---------|------------|
| GHSA-v6hm-64jj-g2vr | < 1.3.3 | ZipSlip路径遍历 | 8 |

**成立条件同 DotNetZip。**

---

## High 级 CVE（建议深度验证）

### Log4net（Apache log4net）

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2018-1285 | < 2.0.13 | XXE（XML外部实体注入）| 7 |

**成立条件**:
```xml
<!-- 触发: 自定义log4net配置文件从用户可控路径加载 -->
<!-- 或: 通过XmlConfigurator.Configure(userControlledXmlElement) -->
<!-- FP: 仅使用内置appender（ConsoleAppender/FileAppender）且配置文件不可外部控制 -->
```

---

### StackExchange.Redis

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2024-46536 | < 2.7.4 | DoS（命令处理竞争）| 5 |
| 历史安全问题 | < 2.0.0 | 未加密传输敏感数据 | 6 |

**配置安全检查**:
```bash
grep -rn "ConfigurationOptions\|ConnectionMultiplexer.Connect" --include="*.cs" . 2>/dev/null | \
  grep -v "ssl=true\|password=" | head -10
# 检测: Redis连接是否启用SSL + 是否设置密码
```

---

### Hangfire.Core

| CVE / GHSA | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----------|---------|---------|------------|
| GHSA-xpjg-hpjf-hg9r | < 1.8.7 | 未授权Dashboard访问 → 任务执行 | 7 |

**成立条件**:
```csharp
// 高危: Dashboard无认证
app.UseHangfireDashboard();  // 无 DashboardOptions.Authorization

// 安全: 有认证配置（不报告）
app.UseHangfireDashboard("/hangfire", new DashboardOptions {
    Authorization = new[] { new HangfireAuthorizationFilter() }
});
```

---

### System.Net.Http（.NET Framework 版）

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2017-0247 | < 4.3.4（.NET Fx 独立包）| TLS证书校验绕过 | 7 |

> 注：仅影响作为独立NuGet包引用的 System.Net.Http，.NET SDK内置版本不受影响。

---

### Microsoft.AspNetCore.* 系列

| CVE | 受影响包 | 影响版本 | 类型 |
|-----|---------|---------|------|
| CVE-2019-0564 | Microsoft.AspNetCore.Server.Kestrel | < 2.1.7 | DoS |
| CVE-2019-0981 | Microsoft.AspNetCore.StaticFiles | < 2.2.3 | 路径遍历 |
| CVE-2019-1075 | Microsoft.AspNetCore.Http | < 2.2.8 | 开放重定向 |
| CVE-2019-0613 | Microsoft.AspNet.Mvc | < 5.2.7 | 代码注入 |

---

### Microsoft.Security.Application（AntiXss）

| CVE / 漏洞说明 | 影响版本 | 漏洞类型 | DKTSS基础分 |
|--------------|---------|---------|------------|
| XSS输出编码不完整 | < 4.3.0 | 跨站脚本（XSS）— 编码库覆盖范围不足 | 6 |

**成立条件**:
```csharp
// 高危: 使用旧版 AntiXss，存在未覆盖的编码场景
// 特别是: HtmlAttributeEncode / JavaScriptEncode 在某些 Unicode 范围不完整
using Microsoft.Security.Application;  // 版本 < 4.3.0
var safe = Sanitizer.GetSafeHtmlFragment(userInput);  // 仍存在绕过向量

// 成立: 版本 < 4.3.0 且用户输入经该库编码后被反射到 HTML 页面
// FP: 版本 >= 4.3.0 / 同时使用了浏览器端 CSP 且 nonce 正确配置
```

**检测命令**:
```bash
grep -rn "Microsoft.Security.Application\|AntiXss" \
  --include="*.csproj" --include="packages.config" . 2>/dev/null
grep -rn "Sanitizer\|AntiXssEncoder\|HtmlAttributeEncode" \
  --include="*.cs" . 2>/dev/null | head -10
```

---

## Medium 级 CVE（视业务重要性决定是否报告）

### System.Text.Encodings.Web

| CVE | 影响版本 | 漏洞类型 | DKTSS基础分 |
|-----|---------|---------|------------|
| CVE-2021-26701 | < 4.5.1 / < 5.0.1 / < 6.0.0 | ReDoS | 4 |

---

### Autofac（IoC容器）

| GHSA | 影响版本 | 漏洞类型 |
|------|---------|---------|
| 无已知CVE | — | 间接影响：若Autofac解析用户可控类型 → 反序列化风险 |

> 注意：Autofac 本身无CVE，但若配合 TypeNameHandling 或动态类型解析使用，
> 可成为反序列化攻击的传递链。

---

## 依赖投毒检测规则

### 私有源混淆攻击（Dependency Confusion）

```bash
# Step 1: 检查 nuget.config 是否配置私有源
cat nuget.config 2>/dev/null | grep -E "add key=|packageSource"

# Step 2: 检测内部包是否也存在于公共源（投毒风险）
# 如果发现内部包名（如 Company.Internal.Utils）可在 nuget.org 搜索到
# → 依赖混淆攻击面存在

# Step 3: 包版本锁定检查
cat packages.lock.json 2>/dev/null | head -50
# 无 packages.lock.json → 浮动版本依赖，存在版本劫持风险
```

**成立条件**:
```
✅ Confirmed: 私有源包名可在公共nuget.org搜索到 + 公共版本高于私有版本
🔍 Hypothesis: 有私有源配置 + 无包版本锁定文件
❌ FP: packages.lock.json存在 + 所有依赖来源明确
```

### Typosquatting（包名抢注）

常见混淆对：
```
Microsoft.AspNet.Cors      → 正确: Microsoft.AspNetCore.Cors
Newtonsoft.JSON            → 正确: Newtonsoft.Json（大小写不同）
BouncyCastle               → 正确: BouncyCastle.Crypto（多种变体）
NLog                       → NLog（本身正确，但 NL0g 等为钓鱼包）
```

---

## Layer 1 快速扫描命令（Phase 0S 完整流程）

```bash
# === 全量依赖提取 ===
echo "=== packages.config ==="
find . -name "packages.config" 2>/dev/null | xargs grep -h 'package id=' 2>/dev/null | \
  grep -oE 'id="[^"]*" version="[^"]*"'

echo "=== .csproj PackageReference ==="
find . -name "*.csproj" 2>/dev/null | xargs grep -h "PackageReference" 2>/dev/null | \
  grep -oE 'Include="[^"]*"[^/]* Version="[^"]*"'

echo "=== Directory.Build.props 全局依赖 ==="
cat Directory.Build.props 2>/dev/null | grep -E "PackageReference|PackageVersion"

# === 官方漏洞扫描（.NET SDK 内置，最准确）===
echo "=== dotnet vuln scan ==="
dotnet list package --vulnerable --include-transitive 2>/dev/null | \
  grep -E "Top-level|Transitive|Critical|High|Moderate|Low"

# === 供应链源检查 ===
echo "=== nuget sources ==="
cat nuget.config 2>/dev/null | grep -E "add key=|packageSources" -A 2

# === 版本锁定状态 ===
ls packages.lock.json 2>/dev/null || echo "⚠️ 无packages.lock.json，存在浮动版本风险"
```

---

## Phase 0S 输出格式

```
[PHASE_0S_SUPPLY_CHAIN]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
依赖总数: {N} | 扫描工具: dotnet list + 矩阵比对
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CVE命中:
  Critical({N}): {包名@版本 → CVE → 风险说明}
  High({N}):     {包名@版本 → CVE → 风险说明}
  Medium({N}):   {包名@版本 → CVE → 风险说明}

依赖投毒评估:
  私有源: {nuget.org官方 / 含私有源(列表)}
  包版本锁定: {packages.lock.json存在/不存在}
  投毒风险: {低/中/高（原因）}

→ 升级 Layer 2 深度验证:
  {列出需要在Layer 2验证调用路径的包}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 修复优先级矩阵

| 优先级 | 条件 | 行动 |
|--------|------|------|
| P0 立即修复 | Critical CVE + 漏洞API被调用 + 公网可达 | 当日升级包版本 |
| P1 本周修复 | High CVE + 漏洞API被调用 | 排入当前迭代 |
| P2 计划修复 | Medium CVE / High CVE但未调用漏洞API | 下个迭代 |
| P3 技术债 | 已停更包（DotNetZip等）/ 无CVE但最佳实践建议迁移 | 季度规划 |

---

*最后更新: 2026-03-23 | 数据来源: NVD / GitHub Advisory / dotnet官方安全公告*
