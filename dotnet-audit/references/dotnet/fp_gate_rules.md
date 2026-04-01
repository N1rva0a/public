# FP Gate 12条规则完整库

> Phase 3 Ralph-Loop 执行完毕后、CRITIC PASS 之前，强制执行全部12条规则。
> 每条规则命中 → 立即降级（移除或降为FP/Info），记入 Claude-Mem。
>
> **设计原则**: 优先压低误报，但不能通过激进降级制造系统性漏报。这12条规则覆盖了 .NET 项目中
> 最高频的误报场景，由真实审计案例提炼。
>
> **执行方式**: 逐条扫描所有待定稿的 reportable 候选（通常是 PROBABLE 或待升级的候选），命中则执行对应处置。

---

## 执行框架

```
[FP_GATE] 开始执行 12 条规则扫描
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
对每个待定稿候选漏洞，依次检查以下12条规则。
规则命中 → 立即降级 + 记录原因 + 跳过后续规则（短路）。
全部规则未命中 → 候选漏洞通过 FP Gate → 进入 CRITIC PASS 或保留在 PROBABLE。
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 认证类 FP 规则（FP-01 ~ FP-03）

### FP-01: [AllowAnonymous] 明确豁免

**规则描述**: 接口有 `[AllowAnonymous]` 注解时，该接口无需认证是**业务设计**，而非漏洞。

**触发条件**:
```csharp
// 触发此规则（应降级为FP）:
[AllowAnonymous]
[HttpGet("api/products")]          // 公开商品列表 → 合理
public IActionResult GetProducts() { ... }

[AllowAnonymous]
[HttpPost("api/auth/login")]       // 登录接口 → 必须匿名
public IActionResult Login([FromBody] LoginDto dto) { ... }
```

**例外场景（不触发此规则，保留审计）**:
```csharp
// 敏感操作有 [AllowAnonymous] → 保留审计
[AllowAnonymous]
[HttpPost("api/user/resetPasswordAdmin")]  // 管理员密码重置无需认证 → 高危，不应FP
public IActionResult ResetAdminPassword() { ... }

[AllowAnonymous]
[HttpDelete("api/admin/users/{id}")]       // 删除用户无需认证 → 高危，不应FP
```

**判定逻辑**:
```
命中FP-01的条件（全部满足）:
1. 接口存在 [AllowAnonymous]
2. 接口功能属于以下类型:
   - 登录/注册/忘记密码（auth流程）
   - 公开查询（无敏感数据）
   - Swagger/健康检查/静态资源
   - 文档生成接口

保留审计的条件（任一满足）:
- 接口涉及修改/删除敏感数据
- 接口路径含 admin/manage/system
- 接口返回敏感个人信息（身份证/密码/token）
```

**检测命令**:
```bash
# 找到 AllowAnonymous 接口，人工判断是否合理
grep -rn -B5 "\[AllowAnonymous\]" --include="*.cs" . 2>/dev/null | \
  grep -E "HttpPost|HttpPut|HttpDelete|admin|manage|reset" | head -20
```

---

### FP-02: 全局 AuthorizeFilter 已覆盖

**规则描述**: `Startup.cs` 或 `Program.cs` 配置了全局 `AuthorizeFilter` 或
`RequireAuthorization()` 时，所有无 `[AllowAnonymous]` 的接口均已受保护。

**触发条件**:
```csharp
// Program.cs / Startup.cs 中存在以下配置之一:
builder.Services.AddControllers(options => {
    options.Filters.Add(new AuthorizeFilter());  // 全局AuthorizeFilter
});

app.MapControllers().RequireAuthorization();     // ASP.NET Core 最小API全局认证

services.AddMvcCore(options => {
    options.Filters.Add(new AuthorizeFilter(policy));
});
```

**处置**:
```
命中此规则时，报告"接口缺少[Authorize]"的漏洞 → 降级为FP
前提: 被报告的接口没有 [AllowAnonymous]
例外: 接口有 [AllowAnonymous] 且为敏感操作 → 不受此规则保护，保留审计
```

**检测命令**:
```bash
grep -rn "AuthorizeFilter\|RequireAuthorization\|AddAuthorization" \
  --include="*.cs" . 2>/dev/null | grep "Startup\|Program\|Filter\|options" | head -10
```

---

### FP-03: 自定义基类权限校验

**规则描述**: 报告的接口所在 Controller 继承自含权限校验逻辑的 BaseController，
但审计时未检查基类实现，误报为"无认证保护"。

**触发条件**:
```csharp
// BaseController（含权限逻辑）
public class BaseApiController : ControllerBase {
    protected override void OnActionExecuting(ActionExecutingContext context) {
        var token = context.HttpContext.Request.Headers["Authorization"];
        if (!ValidateToken(token)) {
            context.Result = new UnauthorizedResult();  // 拦截未授权请求
        }
        base.OnActionExecuting(context);
    }
}

// 具体Controller继承BaseController
public class UserController : BaseApiController {
    // 审计时若未检查继承链，可能误报为无认证
    [HttpGet]
    public IActionResult GetUsers() { ... }
}
```

**检测命令**:
```bash
# 找到被报告接口的Controller基类
grep -rn "class.*Controller.*:\s*\(Base\|ApiBase\|AuthBase\)" --include="*.cs" . 2>/dev/null
# 查看基类是否有OnActionExecuting/权限校验
grep -rn "OnActionExecuting\|OnAuthorization\|IAuthorizationFilter" --include="*.cs" . 2>/dev/null | head -10
```

---

## 反序列化类 FP 规则（FP-04 ~ FP-06）

### FP-04: BinaryFormatter .NET 5+ 默认运行时阻断

**规则描述**: .NET 5/6/7/8 中，`BinaryFormatter` 默认在运行时抛出 `NotSupportedException`，
除非显式配置 `EnableUnsafeBinaryFormatterSerialization=true`。

**触发条件**:
```
目标框架 .NET 5+ 或 .NET 6/7/8
+ 代码中存在 BinaryFormatter.Serialize/Deserialize 调用
+ appsettings.json / runtimeconfig.json 中未设置 EnableUnsafeBinaryFormatterSerialization=true
```

**验证步骤**:
```bash
# Step 1: 确认目标框架
grep -rn "net5\|net6\|net7\|net8\|net9" --include="*.csproj" . 2>/dev/null

# Step 2: 搜索是否显式启用了不安全开关
grep -rn "EnableUnsafeBinaryFormatterSerialization" \
  --include="*.json" --include="*.csproj" --include="*.cs" . 2>/dev/null

# Step 3: 检查 runtimeconfig.json
cat *.runtimeconfig.json 2>/dev/null | grep -i "binaryformatter"
```

**处置规则**:
```
.NET ≥ 5.0 + 未找到 EnableUnsafeBinaryFormatterSerialization=true → FP
.NET ≥ 5.0 + 找到 EnableUnsafeBinaryFormatterSerialization=true → 保留 Confirmed
.NET Framework（任意版本）→ 保留 Confirmed（不适用此规则）
```

---

### FP-05: LosFormatter 在 ASP.NET Core 中不存在

**规则描述**: `LosFormatter` 是 ASP.NET WebForms 专属类，位于 `System.Web`。
ASP.NET Core 不包含 `System.Web`，若反编译代码中出现 `LosFormatter`，
必然是反编译失真（IL翻译错误）导致的误报。

**触发条件**:
```
报告 LosFormatter 漏洞
+ 目标框架为 ASP.NET Core（.NET 5+，或明确无 System.Web 依赖）
```

**验证步骤**:
```bash
grep -rn "System\.Web\b" --include="*.cs" --include="*.csproj" . 2>/dev/null | head -5
# 若无 System.Web 引用 → LosFormatter 报告为反编译失真，FP
```

**处置**: 移除，记入 `Claude-Mem.confirmed_falsepos["LosFormatter-ASP.NET Core-反编译失真"]`

---

### FP-06: ActivitySurrogateSelector 已在 .NET 4.7+ 修复

**规则描述**: `ActivitySurrogateSelector` gadget 链在 .NET Framework 4.7 中被微软修复。
若目标为 .NET Framework ≥ 4.7，此 gadget 无法利用。

**触发条件**:
```
报告 ActivitySurrogateSelector gadget
+ 目标框架 .NET Framework ≥ 4.7（包括4.7.1、4.7.2、4.8）
```

**验证步骤**:
```bash
# 确认框架版本
grep -rn 'targetFramework.*net4[7-9]\|targetFramework.*net4\.7\|targetFramework.*net4\.8' \
  --include="*.config" --include="*.csproj" . 2>/dev/null
```

**处置**: 移除，报告中注明"ActivitySurrogateSelector已在.NET 4.7修复"

---

## 配置类 FP 规则（FP-07 ~ FP-08）

### FP-07: ViewState/MachineKey 在 ASP.NET Core 中不存在

**规则描述**: ViewState 和 MachineKey 是 ASP.NET WebForms（System.Web）专属概念。
ASP.NET Core 完全重写，不存在这两个机制。在 Core 项目中报告相关漏洞 = 反编译失真误报。

**触发条件**:
```
报告 ViewState/MachineKey 相关漏洞（CVE-2023-36434等）
+ 目标为 ASP.NET Core 项目（无 .aspx 文件，无 System.Web 依赖）
```

**验证步骤**:
```bash
# 检查 WebForms 文件
find . -name "*.aspx" -o -name "*.ascx" -o -name "*.ashx" 2>/dev/null | head -5
# 检查 System.Web 依赖
grep -rn "System\.Web\b\|Microsoft\.Web\b" --include="*.csproj" --include="packages.config" . 2>/dev/null | head -5
# 若无 .aspx 且无 System.Web → ViewState/MachineKey 不存在 → FP
```

**处置**: 移除，记入 `Claude-Mem.confirmed_falsepos["ViewState-ASP.NET Core-不存在"]`

---

### FP-08: CSRF AntiForgery 全局策略已启用

**规则描述**: ASP.NET Core 支持全局 AntiForgery 策略（`AutoValidateAntiforgeryToken`）。
若已全局启用，则所有 POST/PUT/DELETE 接口默认受 CSRF 保护。

**触发条件**:
```
报告 CSRF 漏洞（接口缺少 ValidateAntiForgeryToken）
+ Startup/Program 中已配置全局 AntiForgery 策略
```

**检测命令**:
```bash
grep -rn "AutoValidateAntiforgeryToken\|ValidateAntiForgeryToken\|AddAntiforgery" \
  --include="*.cs" . 2>/dev/null | grep -v "//\|[Ignore" | head -10
# 若找到全局配置 → 检查被报告接口是否有 [IgnoreAntiforgeryToken]
```

**处置**:
```
全局 AutoValidateAntiforgeryToken + 接口无 [IgnoreAntiforgeryToken] → FP
接口有 [IgnoreAntiforgeryToken] → 保留审计（需确认是否合理）
```

---

## 国产框架 FP 规则（FP-09 ~ FP-10）

### FP-09: Furion AllowAnonymous + 文档/非业务端点

**规则描述**: Furion 框架生成 Swagger 文档时，会为文档相关接口自动添加 `[AllowAnonymous]`，
或开发者为 Swagger/健康检查等非业务端点手动添加。这是文档系统设计，非漏洞。

**触发条件**:
```
接口同时存在:
1. [AllowAnonymous]
2. 以下任一条件:
   - [ApiDescriptionSettings(IsVisible = false)]（隐藏接口，通常为框架内部）
   - 路由路径含 /swagger/ 或 /api-docs/ 或 /health
   - 方法名含 GetSwaggerDoc / GetApiInfo / HealthCheck / Ping
   - 返回类型为 SwaggerDocument / HealthReport
```

**例外（保留审计）**:
```
接口路径为 /api/xxx 且处理以下业务:
- 修改用户数据（PUT/POST/DELETE）
- 返回包含敏感信息的JSON（password/token/idCard）
- 接口名含 admin/manage/system
```

**检测命令**:
```bash
grep -rn -B3 -A8 "\[AllowAnonymous\]" --include="*.cs" . 2>/dev/null | \
  grep -E "swagger|health|ping|ApiDescriptionSettings|IsVisible.*false" | head -10
```

---

### FP-10: SqlSugar Lambda 表达式自动参数化

**规则描述**: SqlSugar 的 Lambda 表达式 API 内部自动生成参数化 SQL，
无论用户输入是什么，都不会产生 SQL 注入。
误报通常发生在对 `Where(lambda)` 模式的表面扫描中。

**完整安全API白名单**（以下模式全部为FP，禁止报告SQL注入）:
```csharp
// ✅ 全部安全 - Lambda参数化（禁止报告）
db.Queryable<T>().Where(t => t.Field == userInput).ToList();
db.Queryable<T>().Where(t => t.Field.Contains(userInput)).ToList();
db.Queryable<T>().Where(t => SqlFunc.Contains(t.Field, userInput)).ToList();
db.Insertable(entity).ExecuteCommand();
db.Updateable(entity).Where(t => t.Id == id).ExecuteCommand();
db.Deleteable<T>().Where(t => t.Id == id).ExecuteCommand();
db.Queryable<T>().Select(t => new { t.Id, t.Name }).ToList();
db.Queryable<T>().GroupBy(t => t.Category).Select(t => new { ... }).ToList();
db.Queryable<T>().OrderBy(t => t.CreateTime).ToList();
db.Queryable<T>().WhereIF(condition, t => t.Status == status).ToList();  // WhereIF+Lambda

// ⚠️ 需要审查 - 以下可能有SQL注入（不在FP-10保护范围内）
db.Queryable<T>().SqlQueryable($"... {userInput}").ToList();    // 字符串插值
db.Ado.SqlQuery<T>($"SELECT * WHERE Name='{name}'");             // ADO原始SQL
db.Queryable<T>().Where("Status=" + status).ToList();            // 字符串拼接
db.Queryable<T>().WhereIF(cond, "Name='" + name + "'").ToList(); // WhereIF+字符串
```

---

## LLM/AI FP 规则（FP-11 ~ FP-12）

### FP-11: Semantic Kernel 模板变量安全隔离

**规则描述**: Semantic Kernel 的 `{{$variable}}` 模板语法通过变量边界隔离用户输入，
能有效防止 Prompt 注入（变量内容不会被解释为提示词指令）。

**触发条件**（全部满足时 → FP）:
```csharp
// 使用模板变量注入（非字符串拼接）:
await kernel.InvokePromptAsync(
    "Summarize: {{$content}}",              // 模板语法
    new KernelArguments { ["content"] = userInput }  // 变量绑定
);

// 强类型Plugin（有类型约束的参数）:
[KernelFunction]
public string Translate(
    [Description("Text")] string text,     // 有Description且是强类型
    [Description("Language")] string lang) { ... }
```

**需要保留审计（不触发此规则）**:
```csharp
// 字符串拼接（非模板语法）:
var prompt = "Summarize: " + userInput;      // 拼接 → 保留审计
var prompt = $"Summarize: {userInput}";      // 插值 → 保留审计

// 系统提示词含拼接:
var history = new ChatHistory("You help " + userName + " with queries");  // 保留审计
```

**验证步骤**:
```bash
# 确认使用了模板变量语法（而非字符串拼接）
grep -rn "InvokePromptAsync\|CreateFunctionFromPrompt" --include="*.cs" . 2>/dev/null | \
  grep -E '\{\{.*\$|\$".*\{\{' | head -10
# 确认 KernelArguments 绑定了变量
grep -rn "KernelArguments\|new KernelArguments" --include="*.cs" . 2>/dev/null | head -5
```

---

### FP-12: Source Generator 自动生成代码（*.g.cs）

**规则描述**: .NET Source Generator 在构建时自动生成代码文件（`*.g.cs`），
这些文件不可手工修改，漏洞需通过更新 Generator 或其模板修复，
而非直接修改生成文件。处置方式为降级为 Info 并标注来源。

**触发条件**:
```
漏洞代码位于以下路径:
- *.g.cs 文件（Source Generator 生成）
- *.generated.cs 文件
- obj/ 目录下的 *.cs 文件
- {AssemblyName}.GeneratedInterop.cs 等特征名
- [自动生成标注] 文件头含 <auto-generated /> 注释
```

**检测命令**:
```bash
# 确认文件是否为自动生成
head -3 <疑似生成文件> 2>/dev/null | grep -i "auto-generated\|<auto-generated\|generated by"
find . -name "*.g.cs" -o -name "*.generated.cs" 2>/dev/null | head -10
```

**处置**:
```
降级为 Info 级
报告标注: "[自动生成代码] 漏洞位于 Source Generator 生成文件，
         需通过更新 Generator 模板修复，而非手工修改生成文件。
         生成器: {推断的Generator名称}"
```

---

## FP Gate 执行输出格式

```
[FP_GATE] 执行12条规则扫描
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
候选漏洞总数: {N} 个（PROBABLE + HYPOTHESIS + 待升级候选）

逐条规则扫描结果:

FP-01 [AllowAnonymous豁免]:    {命中N个 | 列举接口名} → 移除
FP-02 [全局AuthorizeFilter]:   {命中N个 | 列举接口名} → 移除
FP-03 [基类权限校验]:           {命中N个 | 列举Controller} → 移除
FP-04 [BinaryFormatter已阻断]: {命中N个 | 确认版本+开关状态} → 移除/保留
FP-05 [LosFormatter失真]:      {命中N个} → 移除
FP-06 [ActivitySurrogate修复]: {命中N个 | 版本} → 移除
FP-07 [ViewState Core不存在]:  {命中N个} → 移除
FP-08 [AntiForgery全局启用]:   {命中N个 | 确认全局策略} → 移除
FP-09 [Furion文档端点]:        {命中N个 | 列举路由} → 降为Info
FP-10 [SqlSugar Lambda参数化]: {命中N个 | 列举代码模式} → 移除
FP-11 [SK模板变量隔离]:        {命中N个 | 确认模板语法} → 移除
FP-12 [自动生成代码]:          {命中N个 | 文件路径} → 降为Info

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FP Gate 汇总:
  扫描总计: {N}条规则 × {M}个候选
  移除（FP）: {N}个  |  降级为Info: {N}个  |  通过: {N}个

净化后候选漏洞: {N}个 → 进入 CRITIC PASS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 案例库（真实误报样本）

### 案例1: BinaryFormatter + .NET 6 误报

```
错误报告: "BinaryFormatter反序列化漏洞 (CONFIRMED)"
实际情况: 目标为 .NET 6.0，未配置 EnableUnsafeBinaryFormatterSerialization
正确处置: FP-04 命中 → 移除 → 记入 Claude-Mem

教训: 在 .NET 5+ 扫描 BinaryFormatter 前，必须先确认运行时开关状态。
```

### 案例2: ViewState MachineKey + ASP.NET Core 误报

```
错误报告: "ViewState MachineKey硬编码 (CONFIRMED, DKTSS=10)"
实际情况: 目标为 ASP.NET Core 6.0，machineKey出现在appsettings.json是第三方库配置
正确处置: FP-07 命中 → 移除

教训: 搜索 machineKey 时必须先确认项目类型，Core项目直接FP。
```

### 案例3: SqlSugar Lambda 误报

```
错误报告: "SQL注入: db.Queryable<User>().Where(u => u.Name == name)"
实际情况: SqlSugar Lambda自动参数化，生成 WHERE Name=@name0
正确处置: FP-10 命中 → 移除

教训: 对ORM的Lambda表达式，必须了解框架是否自动参数化，不能凭字面判断。
```

### 案例4: Furion Swagger 接口误报

```
错误报告: "未授权接口: POST /api/swagger/doc → [AllowAnonymous] (HIGH)"
实际情况: Furion框架Swagger文档生成接口，框架设计如此
正确处置: FP-09 命中 → 降为Info

教训: 国产框架的框架内置路由需要单独处理，不能套用通用规则。
```

### 案例5: Source Generator 生成文件误报

```
错误报告: "硬编码连接字符串: DbContextModelSnapshot.g.cs:L234 (MEDIUM)"
实际情况: EF Core Migration自动生成的快照文件，不可手工修改
正确处置: FP-12 命中 → 降为Info，标注"EF Core自动生成"

教训: 扫描前需排除 *.g.cs / obj/ 目录下的自动生成文件。
```

---

*最后更新: 2026-03-23 | 规则数: 12条 | 案例数: 5个*
