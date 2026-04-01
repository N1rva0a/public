# Blazor / SignalR / gRPC 安全审计参考

> 适用：.NET 5+ / ASP.NET Core 3.1+ 项目，`dotnet_version_routing.md` 路由到 Core-Modern 分支时加载。

---

## Blazor Server 安全

### 架构特点与攻击面

Blazor Server 通过 SignalR WebSocket 连接保持 UI 状态，所有 UI 事件以消息形式发送到服务端处理。
**关键区别**：组件代码在服务端运行，数据通过 SignalR 同步到浏览器。

### 高危模式检测

```bash
# 1. 检测 Blazor Server 项目标志
grep -rn "AddServerSideBlazor\|MapBlazorHub" --include="*.cs" .

# 2. 未授权 Blazor 组件（[Authorize] 缺失）
grep -rn "\[Authorize\]" --include="*.razor" . | wc -l
grep -rn "@page " --include="*.razor" . | wc -l
# 如果第一行输出远小于第二行，存在未保护页面

# 3. JavaScript Interop 注入（允许服务端调用任意 JS）
grep -rn "InvokeAsync\|InvokeVoidAsync" --include="*.razor" --include="*.cs" . | \
  grep -v "//.*InvokeAsync"

# 4. 敏感数据在 ProtectedBrowserStorage 中不当存储
grep -rn "ProtectedSessionStorage\|ProtectedLocalStorage" --include="*.cs" .
```

### 成立条件

| 漏洞类型 | 触发条件 | 判定 |
|---------|---------|------|
| 未授权组件访问 | `@page "/admin"` 无 `[Authorize]` + 无全局 AuthorizeRouteView | ✅ Confirmed |
| JS Interop 注入 | `InvokeAsync("eval", userInput)` 或参数含用户可控字符串 | ✅ Confirmed |
| SignalR 会话固定 | 令牌不在认证后重置 | 🔍 Hypothesis |
| 断路器 DoS | 无消息频率限制，高频 UI 事件可打满服务端线程池 | ✅ Confirmed（需测试验证）|

### 审计重点

```csharp
// 危险: JavaScript Interop 传入用户输入
await JS.InvokeVoidAsync("eval", userInput);               // 高危: XSS/SSJS

// 危险: 组件直接从 URL 参数读取并执行操作
[Parameter] public string? SqlQuery { get; set; }          // 高危: 若传入数据库

// 危险: 未授权路由（检查 App.razor 的路由器配置）
<Router AppAssembly="@typeof(App).Assembly">
    <Found Context="routeData">
        <RouteView RouteData="@routeData" />               // 无 AuthorizeRouteView → 未授权
    </Found>
</Router>

// 安全写法
<AuthorizeRouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)">
    <NotAuthorized>
        <RedirectToLogin />
    </NotAuthorized>
</AuthorizeRouteView>
```

---

## SignalR 安全

### 高危模式检测

```bash
# 1. Hub 方法认证缺失
grep -rn "class.*Hub" --include="*.cs" . -l | \
  xargs grep -L "\[Authorize\]"  # 无 [Authorize] 的 Hub 文件

# 2. 客户端可调用的危险 Hub 方法
grep -rn "public.*Task\|public.*void\|public.*async" \
  --include="*.cs" . | grep -v "\[Authorize\]" | grep "Hub"

# 3. 群组管理未授权
grep -rn "Groups.AddToGroupAsync\|Groups.RemoveFromGroupAsync" --include="*.cs" .

# 4. CORS 过于宽松
grep -rn "AllowAnyOrigin\|SetIsOriginAllowed.*true" --include="*.cs" .
```

### 典型漏洞

```csharp
// 高危: Hub 无认证，任何人可调用
public class ChatHub : Hub
{
    public async Task SendMessage(string user, string message)  // 无[Authorize]
    {
        await Clients.All.SendAsync("ReceiveMessage", user, message);
    }
}

// 高危: 用户可将自己加入任意群组
public async Task JoinGroup(string groupName)               // 无权限验证
{
    await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
}

// 高危: 消息未转义直接广播（存储 XSS）
await Clients.All.SendAsync("ReceiveMessage", message);    // message 未 HTML 编码
```

### CORS + SignalR 特殊配置

```bash
# SignalR 需要 WithOrigins 精确匹配（AllowAnyOrigin 会导致 CORS 绕过）
grep -rn "AddSignalR\|MapHub" --include="*.cs" . -A5 | \
  grep -E "AllowAnyOrigin|WithOrigins\(\*"
```

---

## gRPC 安全

### 高危模式检测

```bash
# 1. 认证缺失
grep -rn "class.*Base\b" --include="*.cs" . | grep -v "\[Authorize\]"

# 2. 不安全的 gRPC Web 配置（允许 HTTP/1.1 降级）
grep -rn "UseGrpcWeb\|EnableGrpcWeb" --include="*.cs" .

# 3. proto 文件中的敏感字段暴露
find . -name "*.proto" | xargs grep -l "password\|token\|secret\|private_key"

# 4. 服务端流（Server Streaming）无流量控制
grep -rn "IServerStreamWriter" --include="*.cs" .
```

### 典型漏洞

```csharp
// 高危: 直接反射 proto 中的用户输入到 SQL
public override async Task<Reply> GetUser(Request req, ServerCallContext ctx)
{
    var sql = $"SELECT * FROM Users WHERE Name='{req.Username}'";  // SQLi
    ...
}

// 高危: 元数据泄露（gRPC reflection 服务开启）
// Program.cs:
app.MapGrpcReflectionService();  // 生产环境应禁用，暴露所有服务定义
```

---

## CORS 策略专项审计

```bash
# 检查所有 CORS 配置
grep -rn "AddCors\|WithOrigins\|AllowAnyOrigin\|AllowAnyHeader\|AllowCredentials" \
  --include="*.cs" . 

# 常见危险组合
grep -rn "AllowAnyOrigin.*AllowCredentials\|AllowCredentials.*AllowAnyOrigin" --include="*.cs" .
# AllowAnyOrigin() + AllowCredentials() 在 ASP.NET Core 中会抛异常（框架保护）
# 但 SetIsOriginAllowed(_ => true) + AllowCredentials() 不会报错 → 高危
```

### 成立条件

| CORS 配置 | 判定 |
|-----------|------|
| `SetIsOriginAllowed(_ => true)` + `AllowCredentials()` | ✅ Confirmed（任意源凭证发送）|
| `WithOrigins("https://trusted.com")` + `AllowCredentials()` | ❌ 正确配置 |
| `AllowAnyOrigin()` + `AllowCredentials()` | ❌ ASP.NET Core 框架阻断（抛异常）|
| `AllowAnyOrigin()` 无 `AllowCredentials()` | ⚠️ Low（无凭证，影响有限）|
| `WithOrigins` 含 `null` 来源或空字符串 | 🔍 Hypothesis（检查浏览器 null 来源绕过）|

---

## 输出格式（发现时追加到 LAYER2_AUDIT）

```
[ASPNETCORE_MODERN]
Blazor: {组件总数 N / 未保护 N / JS Interop 风险 N}
SignalR Hub: {Hub总数 N / 未保护 N / 群组权限风险 N}
gRPC: {服务数 N / Reflection 开启: 是/否 / 认证缺失 N}
CORS: {策略数 N / 危险配置 N / 详情: ...}
```
