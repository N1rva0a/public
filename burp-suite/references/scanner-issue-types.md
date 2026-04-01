# Scanner Issue Types — 分类 + 手工验证步骤
# 被调用方: AI-6（报告生成）/ Scanner Review 时读取
# 加载时机: 处理 burp:get_scanner_issues() 结果时，或审查自动扫描发现时

---

## 使用说明

```
Burp Scanner 返回的 issue 不等于已确认漏洞。
本文件定义每类 issue 的:
  1. 置信度评估（Scanner结论可靠性）
  2. 手工验证步骤（至少一步必须执行）
  3. AI-3调用点（何时将结果移交响应判定）
  4. 误报率参考（FP Gate触发概率）

调用顺序:
  get_scanner_issues() → 按 issue_type 分类 → 查本文件 → 手工验证 → AI-3判定
```

---

## 高置信度 Issue（置信度：高，误报率<20%）

### SI-01: SQL Injection

```
Scanner类型名: "SQL injection"
Scanner置信度: 确定/固定
误报率参考: <15%（有错误信息时接近0%）

手工验证步骤（至少完成步骤1）:
  步骤1 快速确认: 手动重放 Scanner 使用的 payload → 观察同样响应
  步骤2 类型确认: 按 sqli-engine.md Phase 0-1 确定注入类型
  步骤3 危害证明: 提取 DB版本+用户名（参考 sqli-engine.md Phase 3）
  步骤4 五条件核查: sqli-engine.md Phase 5 清单

常见误报场景（FP Gate）:
  - 参数含SQL关键词但不可注入（搜索框含 SELECT 字样）
  - 返回格式包含SQL错误样式的自定义消息
  - Scanner时延测试受到服务端性能影响（FP Gate Rule 3）

AI-3 移交条件: 步骤1确认响应一致 → 移交AI-3最终判定
```

### SI-02: Cross-Site Scripting (XSS)

```
Scanner类型名: "Cross-site scripting (reflected)" / "Cross-site scripting (stored)"
Scanner置信度: 确定/固定
误报率参考: <20%

手工验证步骤:
  步骤1: 在浏览器中重放 → 确认 payload 在DOM中实际执行（不仅是反射）
  步骤2: 检查响应上下文 → payload处于何种HTML/JS/CSS上下文中
  步骤3: 触发实际危害 → alert(document.cookie) 或 fetch 外带
  步骤4: 对于存储型 → 验证其他用户访问时同样触发

常见误报场景:
  - payload被 HTML 实体编码后反射（&lt;script&gt; 非可执行）
  - payload在JavaScript注释块中（// 注释）
  - payload在 textarea/pre/code 标签内（通常无执行）
  → FP Gate Rule 5 触发

AI-3 移交条件: 步骤1证实浏览器中确实执行 → CONFIRMED
```

### SI-03: Path Traversal

```
Scanner类型名: "Path traversal"
Scanner置信度: 确定
误报率参考: <25%

手工验证步骤:
  步骤1: 重放 Scanner 的 payload → 确认响应中含 /etc/passwd 或 Windows系统文件内容
  步骤2: 测试写入能力（若为文件写入端点）:
          尝试写入 ../../tmp/pentest_canary.txt
  步骤3: 评估可访问范围（Web根目录/系统文件/配置文件）

常见误报场景:
  - Scanner 路径被服务端白名单过滤但返回了"文件不存在"（非路径穿越）
  - 测试环境文件内容为空（正常文件不存在）
```

---

## 中置信度 Issue（置信度：中，误报率20-50%，必须手工验证）

### SI-04: SSRF

```
Scanner类型名: "Server-side request forgery"
Scanner置信度: 暂定
误报率参考: 30%

手工验证步骤（必须OOB验证）:
  步骤1: generate_collaborator_payload(customData="SSRF_VERIFY")
  步骤2: 将 Collaborator URL 注入目标参数
  步骤3: 等待15s → get_collaborator_interactions(payloadId=...)
  步骤4 有DNS回调: → CONFIRMED（记录 collaborator_interaction_id）
  步骤4 无回调: → 尝试内网地址（127.0.0.1/metadata服务）

FP Gate Rule 7: 仅DNS回调需二次确认
AI-3 移交条件: 有OOB证据 → CONFIRMED / 仅响应差异 → HYPOTHESIS
```

### SI-05: XXE

```
Scanner类型名: "XML injection" / "External service interaction"
Scanner置信度: 暂定
误报率参考: 35%

手工验证步骤:
  步骤1: 确认应用确实解析XML（Content-Type: application/xml + XML body）
  步骤2: 发送基础XXE: <!DOCTYPE test [<!ENTITY x SYSTEM "file:///etc/passwd">]><test>&x;</test>
  步骤3 无回显: → OOB XXE（collaborator + 带外DTD）
  步骤4: 确认 file:// 协议可用（Linux目标: /etc/passwd / Windows: C:\Windows\System32\drivers\etc\hosts）

常见误报:
  - 应用接受XML但未配置外部实体解析（XMLReader with LIBXML_NOENT=false）
  - Scanner误将JSON字段中的XML注入标记为XXE
```

### SI-06: Open Redirect

```
Scanner类型名: "Open redirection (reflected)"
Scanner置信度: 暂定
误报率参考: 25%

手工验证步骤:
  步骤1: 手动发送 redirect参数=https://evil.com
  步骤2: 检查响应: Location: https://evil.com → ✅ 确认
  步骤3: 危害评估:
         有效 → 钓鱼/OAuth token盗取场景
         仅路径跳转无危害 → 降级或FP

常见误报:
  - 跳转到相对路径而非绝对URL（/evil.com 不等于 //evil.com）
  - 有效域名白名单（只允许跳转到 *.target.com）
```

### SI-07: CSRF

```
Scanner类型名: "Cross-site request forgery"
Scanner置信度: 暂定
误报率参考: 40%

手工验证步骤:
  步骤1: 确认请求无CSRF Token 或 Token可预测
  步骤2: 确认请求使用 Cookie 认证（Bearer Token不受CSRF影响）
  步骤3: 构造跨站请求 → 在另一个origin发送该请求 → 检查是否成功
  步骤4: 检查 SameSite Cookie属性（Strict/Lax → 通常无法CSRF）

常见误报:
  - SameSite=Strict/Lax 的现代浏览器实际上无法利用
  - 需要用户交互的操作（下载文件不算危害）
  - API接口不带Cookie（用Authorization: Bearer）
```

### SI-08: HTTP Request Smuggling

```
Scanner类型名: "HTTP request smuggling"
Scanner置信度: 暂定
误报率参考: 45%

手工验证步骤（复杂，需专项工具）:
  步骤1: 确认存在前端代理（Nginx/CDN + 后端应用服务器）
  步骤2: 测试 CL.TE vs TE.CL:
         CL.TE: Content-Length在前端生效，Transfer-Encoding在后端生效
         TE.CL: Transfer-Encoding在前端，Content-Length在后端
  步骤3: 发送"时间差探针"验证走私效果（Burp Repeater Group 并发）
  步骤4: 无法简单确认时 → 标记HYPOTHESIS，建议专项测试

推荐工具: Turbo Intruder + HTTP/2降级测试
```

---

## 低置信度 Issue（置信度：低，误报率>50%，需深度验证）

### SI-09: Information Disclosure

```
Scanner类型名: "Version disclosure" / "Password field with autocomplete enabled"
Scanner置信度: 暂定
误报率参考: 60%（取决于子类型）

手工验证步骤:
  技术版本泄露: 
    确认版本是否有已知CVE → 搜索 NVD/Seebug
    无CVE → 降为低危信息性发现
  敏感路径泄露 (/backup/.git/.env):
    直接访问确认文件存在且可读
  API密钥/凭证泄露:
    验证密钥有效性（向对应服务发送测试请求）

危害区分:
  含CVE的版本泄露 → 高危（可链接利用）
  仅版本号泄露无CVE → 低危
  开发路径泄露 → 中危（侦察价值）
```

### SI-10: CORS Misconfiguration

```
Scanner类型名: "Cross-origin resource sharing"
Scanner置信度: 低
误报率参考: 55%

手工验证步骤:
  步骤1: 发送 Origin: https://evil.com → 检查响应头
  步骤2: 检查 Access-Control-Allow-Origin: https://evil.com （直接反射）
  步骤3: 检查 Access-Control-Allow-Credentials: true
  步骤4: 两者都有 → 构造 XHR 跨站请求测试实际数据读取能力

判定:
  Allow-Origin:* + Allow-Credentials:true → 浏览器会拒绝（规范限制，FP）
  Allow-Origin:evil.com + Allow-Credentials:true → 真实漏洞 ✅
  Allow-Origin:null + Allow-Credentials:true → 可利用（沙箱iframe） ✅
```

### SI-11: Clickjacking

```
Scanner类型名: "Clickjacking (UI redressing)"
Scanner置信度: 低
误报率参考: 70%（取决于功能）

手工验证步骤:
  步骤1: 确认缺少 X-Frame-Options 或 CSP frame-ancestors
  步骤2: 确认目标页面有敏感操作（不只是展示型页面）
  步骤3: 构造 iframe 覆盖 PoC:
         <iframe src="https://target.com/sensitive_action" style="opacity:0.1;position:absolute;top:0;left:0">
  步骤4: 确认用户在不知情情况下可被诱导点击

降级标准:
  登录页面的Clickjacking → 低危（需用户已登录）
  账户删除/转账的Clickjacking → 高危
  纯展示页面 → 信息性（不报漏洞）
```

---

## Scanner 结果批量处理流程

```
收到 get_scanner_issues() 结果后的处理顺序:

Step 1: 按 severity 分组
  Critical/High → 优先验证
  Medium → 次优先
  Low/Info → 批量评估，抽样验证

Step 2: 按置信度分类（查本文件对应SI-XX）
  置信度"确定" → 走手工验证快速通道
  置信度"暂定" → 必须完成对应手工验证步骤
  置信度"低" → 评估是否值得投入验证时间

Step 3: AI-3 移交判定
  手工验证证实 → AI-3 输出 CONFIRMED
  无法证实 → AI-3 输出 HYPOTHESIS/FP
  FP Gate命中 → 直接标记 FALSE_POSITIVE + 原因

Step 4: 报告分类（AI-6）
  CONFIRMED → 主报告漏洞清单
  HYPOTHESIS → 附录"待进一步验证"
  FALSE_POSITIVE → 误报剔除清单（含FP原因）

Step 5: BCheck生成（AI-12）
  CONFIRMED且类型可规则化（SQLi/XSS/SSRF）→ 自动生成BCheck
```

---

## 与 code-audit 的映射关系

```
Scanner Issue Type     → code-audit 对应维度/轨道          → 联动方式
-------------------      -------------------------------    -------------------------
SQL injection          → D1 injection family               → phase 2/3 动态确认
XSS reflected/stored   → D1 injection family               → 浏览器/渲染证据确认
Path traversal         → D5 file operations                → 文件读取/路径规范化确认
SSRF                   → D6 SSRF/outbound reachability     → OOB/网络行为确认
XXE                    → D1 injection family               → XML parser 行为专项
IDOR/BOLA              → D15 object access                 → 归属/租户边界确认
CSRF/CORS/Auth drift   → D2/D3 control-driven review       → 交回静态控制模型协同
LLM/MCP issues         → D11-D14 dynamic AI tracks         → 联动 MCP/LLM 专项
HTTP Request Smuggling → 动态专项（无固定 D 映射）        → 独立动态报告/用户确认
Clickjacking           → 动态专项（前端暴露）              → Burp-only finding

发现 Scanner Issue 且有对应 code-audit VULN-N:
  → 直接进入第二阶段验证（跳过AI-1攻击面分析）
  → 更新 JOINT_SESSION.surface_map / handoff task state，避免直接写底层 exploit_queue 结构
```

---

## DKTSS 评分参考（Scanner发现的基础分）

```
漏洞类型              基础DKTSS    上调条件                    下调条件
-------------------   ----------   -------------------------   ---------------
SQL Injection (Error) 8.5          有DB Root权限 → +0.5        仅读/无权限 → -1
SQL Injection (Blind) 7.5          OOB成功 → +0.5              仅bool无数据提取 → -0.5
XSS Stored            8.0          影响所有用户 → +0.5          需要登录才触发 → -1
XSS Reflected         6.5          无CSP → +0.5                有强CSP → -2
SSRF (OOB only)       6.0          能访问元数据服务 → +2        仅DNS无HTTP → -1
SSRF (内网访问)       8.0          能访问数据库 → +1
Path Traversal        7.5          能读取敏感配置 → +1          只能读取Web文件 → -1
XXE                   7.0          有file://协议 → +0.5        仅错误信息 → -1
CSRF (敏感操作)       7.0          无SameSite保护 → +0.5       需用户登录 → 已含
Open Redirect         5.5          可链接OAuth盗取 → +2         仅路径跳转 → -3
CORS (含Credentials)  7.5          含高危API → +0.5
Clickjacking          5.0          含高危操作 → +2              仅展示页 → -3
```
