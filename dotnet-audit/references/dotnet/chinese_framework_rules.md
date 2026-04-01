# 国产 .NET 框架安全规则库

> Phase 0E 触发后加载。覆盖 Furion、SqlSugar、FreeSql、ABP、Masa.Framework 等
> 国内主流 .NET 框架的专属安全规则、高危模式、FP判定和修复建议。
>
> **激活条件**: Phase 0 RECON 检测到国产框架指纹（包名/中文注释/拼音类名）时加载。

---

## 框架识别指纹

```bash
# 检测国产框架
grep -rn "Furion\|SqlSugar\|FreeSql\|Masa\.Framework\|Admin\.NET\|Magic\.NET\|YiShaAdmin" \
  --include="*.csproj" --include="packages.config" . 2>/dev/null

# 检测典型初始化代码
grep -rn "Inject()\|AddSqlSugar\|AddFreeRedis\|UseFreeSql\|AddFurion" \
  --include="*.cs" . 2>/dev/null | head -10

# ABP框架检测
grep -rn "AbpModule\|IAbpApplication\|DependsOn.*Module" \
  --include="*.cs" . 2>/dev/null | head -5
```

---

## Furion 框架

### 框架简介
Furion 是国内广泛使用的 ASP.NET Core 快速开发框架，内置动态API、数据库操作、
权限管理等能力。常见于政府、医疗、企业ERP等系统。

### 高危模式 — SQL 注入

#### FUR-SQL-01: SqlProxy 动态SQL执行
```csharp
// 高危: 用户输入直接参与SQL构建
var result = "SELECT * FROM Users WHERE Name='" + userName + "'"
    .SqlQueryAsync<User>();

// 高危: Ado 原始SQL
var data = Db.Ado.SqlQuery<User>($"SELECT * FROM Users WHERE Id={userId}");

// 安全（FP）: 参数化
var data = Db.Ado.SqlQuery<User>("SELECT * FROM Users WHERE Id=@id", new { id = userId });
```

**检测命令**:
```bash
grep -rn '\.SqlQuery\b\|\.SqlQueryAsync\b\|Db\.Ado\.Execute' \
  --include="*.cs" . 2>/dev/null | grep -v '@\|new {' | head -20
```

**成立条件**:
```
✅ Confirmed: .SqlQuery(用户输入参与字符串拼接) → SQL注入
❌ FP: .SqlQuery("...", new { param = userInput }) → 参数化，安全
```

#### FUR-SQL-02: Repository 原始SQL
```csharp
// 高危: 仓储层暴露原始SQL
var repo = Db.GetRepository<User>();
repo.SqlQuery($"SELECT * FROM Users WHERE Department='{dept}'");

// 安全（FP）:
repo.Where(u => u.Department == dept).ToList();  // LINQ参数化
```

---

### 高危模式 — 权限绕过

#### FUR-AUTH-01: [AllowAnonymous] 滥用与Swagger泄露
```csharp
// 需要关注: 大量接口标记 AllowAnonymous
[AllowAnonymous]
[HttpPost("api/user/resetPassword")]  // 敏感操作无需认证 → 高危

// 低风险（文档路由，FP）:
[AllowAnonymous]
[ApiDescriptionSettings(IsVisible = false)]  // Swagger隐藏
```

#### FUR-AUTH-02: 动态API权限配置缺失
Furion 支持动态 WebAPI（无需手写Controller），检查 `IDynamicApiController` 实现：
```csharp
// 需检查: 动态API是否有权限配置
public class UserService : IDynamicApiController {
    // 检查: 是否有 [Authorize] 或 SecurityDefine 配置
    public User GetUserInfo(int userId) { ... }  // 无权限控制 → 高危
}
```

**检测命令**:
```bash
grep -rn "IDynamicApiController\|: IDynamicApiController" --include="*.cs" . 2>/dev/null | \
  xargs -I{} grep -l "{}" | xargs grep -L "\[Authorize\]\|SecurityDefine" 2>/dev/null | head -10
```

#### FUR-AUTH-03: JWT 种子密钥硬编码
```csharp
// 常见于 appsettings.json
{
  "JWTSettings": {
    "SecretKey": "your-256-bit-secret-key-here-change-this"  // ← 默认示例值未修改
  }
}
```

**检测命令**:
```bash
grep -rn "SecretKey\|JwtKey\|TokenKey" --include="*.json" --include="*.config" . 2>/dev/null | \
  grep -iv "placeholder\|changeme\|example" | head -10
```

---

### 高危模式 — 文件操作

#### FUR-FILE-01: 文件下载路径遍历
```csharp
// 高危: 直接使用用户传入的文件名
[AllowAnonymous]
public IActionResult DownloadFile(string fileName) {
    var path = Path.Combine(_uploadDir, fileName);  // fileName 未过滤 ../
    return PhysicalFile(path, "application/octet-stream");
}

// 安全（FP）:
var safeName = Path.GetFileName(fileName);  // 剥离路径
var fullPath = Path.GetFullPath(Path.Combine(_uploadDir, safeName));
if (!fullPath.StartsWith(_uploadDir)) return BadRequest();
```

---

## SqlSugar 框架

### 框架简介
SqlSugar 是国内最流行的 .NET ORM 框架之一，以"糖"语法和高性能著称。
广泛用于中小型项目，部分项目直接在 Service 层暴露原始SQL能力。

### 高危模式 — SQL 注入

#### SSG-SQL-01: SqlQueryable 原始SQL（最高危）
```csharp
// 高危: 字符串插值拼接用户输入
var list = db.SqlQueryable<User>($"SELECT * FROM Users WHERE Name='{name}'")
    .ToList();

// 高危: 字符串加法拼接
var sql = "SELECT * FROM Orders WHERE Status='" + status + "'";
var orders = db.SqlQueryable<Order>(sql).ToList();

// 安全（FP）: 使用参数
var list = db.SqlQueryable<User>("SELECT * FROM Users WHERE Name=@name")
    .AddParameters(new SugarParameter("@name", name))
    .ToList();
```

**检测命令**:
```bash
grep -rn '\.SqlQueryable\s*(' --include="*.cs" . 2>/dev/null | grep -v '@name\|SugarParameter' | head -20
grep -rn '\.Ado\.SqlQuery\s*\|\.Ado\.ExecuteCommand\s*' --include="*.cs" . 2>/dev/null | \
  grep -v '@\|SugarParameter' | head -20
```

#### SSG-SQL-02: Ado 直接执行（高危）
```csharp
// 高危: ExecuteCommand 直接执行用户构造SQL
db.Ado.ExecuteCommand($"UPDATE Users SET Role='{role}' WHERE Id={id}");
db.Ado.SqlQuery<User>($"SELECT * FROM Users WHERE {filterField}='{filterValue}'");

// 安全（FP）:
db.Ado.ExecuteCommand("UPDATE Users SET Role=@role WHERE Id=@id",
    new SugarParameter("@role", role), new SugarParameter("@id", id));
```

#### SSG-SQL-03: WhereIF 条件注入
```csharp
// 高危: 直接将用户输入作为 SQL 片段
db.Queryable<User>()
    .WhereIF(!string.IsNullOrEmpty(condition), condition)  // condition 是用户SQL片段 → 高危
    .ToList();

// 安全（FP）:
db.Queryable<User>()
    .WhereIF(!string.IsNullOrEmpty(name), u => u.Name == name)  // Lambda参数化
    .ToList();
```

#### SSG-SQL-04: Lambda 参数化（FP规则 FP-10 详情）
```csharp
// 以下全部为 ORM 自动参数化，禁止报告 SQL 注入:
db.Queryable<User>().Where(u => u.Name == userInput).ToList();
db.Queryable<User>().Where(u => u.Id == userId).ToList();
db.Insertable(entity).ExecuteCommand();
db.Updateable(entity).ExecuteCommand();
db.Deleteable<User>().Where(u => u.Id == id).ExecuteCommand();
// 以上均由SqlSugar内部转换为参数化SQL，无注入风险
```

---

### 高危模式 — 越权（IDOR）

#### SSG-IDOR-01: 数据权限过滤缺失
```csharp
// 高危: 查询订单时未校验归属
public Order GetOrder(int orderId) {
    return db.Queryable<Order>().First(o => o.Id == orderId);
    // 未检查 o.UserId == currentUserId → 任意订单查看
}

// 安全（FP）:
public Order GetOrder(int orderId, int currentUserId) {
    return db.Queryable<Order>()
        .First(o => o.Id == orderId && o.UserId == currentUserId);
}
```

**检测命令**:
```bash
# 找到查询方法但未过滤用户归属的模式
grep -rn '\.First\s*(.*Id\s*==\|\.Single\s*(.*Id\s*==' --include="*.cs" . 2>/dev/null | \
  grep -v "UserId\|OwnerId\|CreatedBy\|currentUser" | head -20
```

---

## FreeSql 框架

### 框架简介
FreeSql 是功能完整的国产 ORM，支持多数据库，提供 CodeFirst/DbFirst 两种模式。
在微服务架构中常见，部分项目使用其 ADO 扩展执行原始SQL。

### 高危模式 — SQL 注入

#### FSQ-SQL-01: Where 原始SQL（最高危）
```csharp
// 高危: 将用户输入作为SQL片段传入Where
fsql.Select<User>()
    .Where($"Name='{name}' OR 1=1")  // SQL注入
    .ToList();

// 高危: 使用 .Where(rawSql) 重载
fsql.Select<User>().Where("Status=" + status).ToList();

// 安全（FP）:
fsql.Select<User>().Where(u => u.Name == name).ToList();  // Lambda
fsql.Select<User>().Where("Name=@name", new { name }).ToList();  // 命名参数
```

**检测命令**:
```bash
grep -rn '\.Where\s*(\s*["\$]' --include="*.cs" . 2>/dev/null | \
  grep -v '@\|new {' | head -20
grep -rn 'fsql\.Ado\|IFreeSql.*Ado\b' --include="*.cs" . 2>/dev/null | head -10
```

#### FSQ-SQL-02: ToSql() 调试接口泄露
```csharp
// 中危: 将ORM生成的SQL直接返回给前端（泄露表结构）
[HttpGet("debug/sql")]
public string GetSql(string filter) {
    return fsql.Select<User>().Where(u => u.Name == filter).ToSql();
}
```

#### FSQ-SQL-03: ExecuteAsync 原始执行
```csharp
// 高危: 执行用户构造的SQL
await fsql.Ado.ExecuteNonQueryAsync($"DELETE FROM {tableName} WHERE {condition}");
```

---

### 高危模式 — 多租户数据隔离绕过

#### FSQ-MT-01: Filter 全局过滤器禁用
```csharp
// 高危: 手动禁用了多租户过滤器
using (fsql.DisableGlobalFilter("tenant")) {
    // 绕过租户过滤 → 跨租户数据访问
    var allUsers = fsql.Select<User>().ToList();
}
// 检查是否有业务合理性，若无 → 越权漏洞
```

**检测命令**:
```bash
grep -rn "DisableGlobalFilter\|DisableFilter" --include="*.cs" . 2>/dev/null | head -10
```

---

## ABP Framework（国际框架，国内广泛使用）

### ABP 特有安全模式

#### ABP-PERM-01: 权限声明缺失
```csharp
// 高危: ApplicationService 方法未声明权限
public class OrderAppService : ApplicationService, IOrderAppService {
    public async Task<OrderDto> GetAsync(Guid id) {
        // 未调用 CheckPolicyAsync 或 [Authorize(Policy=...)]
        return await _orderRepository.GetAsync(id);
    }
}

// 安全（FP）:
[Authorize(OrdersPermissions.Orders.Default)]
public async Task<OrderDto> GetAsync(Guid id) { ... }
// 或:
await AuthorizationService.CheckAsync(OrdersPermissions.Orders.Default);
```

**检测命令**:
```bash
grep -rn ": ApplicationService\|: CrudAppService" --include="*.cs" . 2>/dev/null | \
  xargs -I{} grep -l "$(echo {} | sed 's/.*\///')" 2>/dev/null | \
  xargs grep -L "\[Authorize\]\|CheckPolicyAsync\|CheckAsync" 2>/dev/null | head -10
```

#### ABP-REPO-01: 仓储绕过软删除
```csharp
// 中危: 绕过全局软删除过滤器
using (_dataFilter.Disable<ISoftDelete>()) {
    var deletedData = await _repo.GetListAsync();  // 查询到已软删除数据
}
// 检查是否有业务场景，若暴露给前端且无权限保护 → 中危
```

---

## 中文语境代码审计 SOP

### 拼音命名映射参考

审计中文项目时，根据拼音方法名推断业务语义：

| 拼音名称模式 | 可能业务语义 | 重点关注 |
|------------|-----------|---------|
| `dengLu/DengLu/denglu` | 登录 | 认证绕过/暴力破解保护 |
| `zhuCe/ZhuCe` | 注册 | 用户枚举/邮箱验证 |
| `xiuGai/xiugai` | 修改 | 越权修改（IDOR）|
| `shanChu/delete` | 删除 | 越权删除/软删除绕过 |
| `shangChuan/upload` | 上传 | 文件上传漏洞 |
| `xiazai/download` | 下载 | 路径遍历/未授权下载 |
| `chongZhi/chongzhi` | 重置 | 密码重置逻辑缺陷 |
| `quanXian/quanxian` | 权限 | 权限配置核心代码 |
| `mi/miMa/mima` | 密码/密钥 | 明文存储/弱加密 |
| `zhiFu/zhifu` | 支付 | 金额篡改/重放攻击 |
| `guanLi/guanli` | 管理 | 管理功能是否有权限保护 |
| `peizhi/config` | 配置 | 敏感配置泄露 |

---

### 中文注释提取 → 业务逻辑理解

```bash
# 提取中文注释（密集注释区域 = 关键业务逻辑）
grep -rn --include="*.cs" -B1 -A1 "//.*[\u4e00-\u9fff]" . 2>/dev/null | \
  grep -E "登录|权限|密码|管理员|超级管理|跳过验证|不需要" | head -30

# 提取特殊注释（TODO/HACK/临时处理 → 安全债务）
grep -rn --include="*.cs" \
  -E "//\s*(TODO|FIXME|HACK|临时|暂时跳过|待处理|安全问题|先注释|测试用)" \
  . 2>/dev/null | head -20
```

**高危中文注释信号**:
```
"// 暂时注释掉权限验证"    → 认证绕过
"// 测试用，不要提交"       → 调试代码残留
"// 先放开，后面再加权限"   → 未保护接口
"// 直接执行SQL，效率高"    → 潜在SQL注入
"// 跳过token验证"          → JWT绕过
```

---

## FP 规则对照（国产框架专属）

### FP-09: Furion AllowAnonymous + ApiDescriptionSettings

**完整规则**:
```
触发条件:
  接口同时存在:
  1. [AllowAnonymous] 注解
  2. [ApiDescriptionSettings(IsVisible = false)] 或 Route 路径为 /swagger/... /api-docs/...
  或 方法名为 GetSwaggerDoc / GetApiDoc 等文档生成相关

成立则: 文档生成路由，非业务接口 → 降为 Info 级
例外: 若接口路径为 /api/xxx 且处理业务数据 → 保留 High
```

### FP-10: SqlSugar Lambda 参数化

**完整规则**:
```
触发条件: 代码使用 SqlSugar 的 Lambda 表达式 API（非原始SQL）:
  - .Where(u => u.Field == userInput)
  - .Select(u => new { u.Id, u.Name })
  - .Insertable(entity).ExecuteCommand()
  - .Updateable(entity).Where(u => u.Id == id).ExecuteCommand()
  - .Deleteable<T>().Where(u => u.Id == id).ExecuteCommand()

成立则: ORM自动参数化，无SQL注入风险 → 移除
注意: .SqlQueryable() / .Ado.ExecuteCommand() 不在此规则范围，单独判断
```

---

*最后更新: 2026-03-23*
