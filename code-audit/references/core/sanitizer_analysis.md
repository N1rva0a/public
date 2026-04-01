# Sanitizer 充分性语义推理 — 详细参考

> 本文件是 SKILL.md Phase 3D 的扩展参考。核心原则：净化是否充分取决于漏洞类型 × 输出上下文 × 旁路模式三者共同决定，而非函数名。

---

## 1. 净化类型 × 漏洞类型匹配矩阵

| 漏洞类型 | 有效净化 | 常见无效净化（不能阻止该类型） |
|---------|---------|----------------------------|
| SQL 注入 | 参数化查询 / `addslashes` + 正确引号 | `htmlspecialchars`、长度限制 |
| XSS | `htmlspecialchars(ENT_QUOTES)` / CSP | SQL 转义、`addslashes`、`strip_tags`（不完整） |
| 命令注入 | `escapeshellarg` / `escapeshellcmd` / 白名单 | HTML 编码、SQL 转义 |
| Path Traversal | `realpath()` + 基目录前缀校验 | 仅过滤 `../`（可被 `....//` 绕过） |
| SSRF | URL 白名单 + 禁止私有 IP 段 | 字符串长度限制、关键词过滤 |
| SSTI | 禁用反射 / 沙箱化模板引擎 | 正则过滤部分字符（通常可绕过） |
| XXE | 禁用外部实体 (`LIBXML_NOENT` = false) | 仅过滤 `<!ENTITY` 字符串 |
| 反序列化 | 白名单类名校验 / HMAC 签名 | 仅过滤部分 payload 字符 |
| Open Redirect | 白名单域名校验 | 仅过滤 `http://`（可用 `//` 绕过） |
| LDAP 注入 | `ldap_escape()` | `htmlspecialchars`、SQL 转义 |

**判定原则**：净化类型与漏洞类型不匹配 → 直接视为无净化，标记 Confirmed。

---

## 2. 输出上下文覆盖详细规则

### 2.1 XSS 输出上下文矩阵

| 输出位置 | 所需净化 | `htmlspecialchars` 是否足够 |
|---------|---------|--------------------------|
| HTML 元素内容 `<div>USER</div>` | HTML 编码 | ✅ 足够 |
| HTML 属性（带引号）`<a href="USER">` | HTML 编码 | ✅ 足够 |
| HTML 属性（无引号）`<a href=USER>` | HTML 编码 + 引号包裹 | ⚠️ 需确认有引号 |
| JS 字符串 `var x = "USER"` | JS 编码 / `json_encode` | ❌ 不足（`<` `>` 编码不阻止 JS 注入） |
| JS 内联 `<script>USER</script>` | JS 编码 | ❌ 不足 |
| CSS 属性 `style="USER"` | CSS 编码 | ❌ 不足 |
| URL 参数 `href="?q=USER"` | `urlencode` | ❌ 不足 |
| URL 路径 `href="/path/USER"` | `rawurlencode` + 白名单 | ❌ 不足 |
| `data-*` 属性 | HTML 编码 | ✅ 足够（仅JS读取时需额外处理） |

### 2.2 SQL 输出上下文矩阵

| 使用位置 | 有效净化 | 说明 |
|---------|---------|------|
| 字符串字面量 `WHERE name = 'USER'` | `addslashes` / 参数化 | 必须有引号包裹，否则 addslashes 失效 |
| 数值字面量 `WHERE id = USER` | `intval()` / 参数化 | 不能用字符串转义，必须类型转换 |
| IN 子句 `WHERE id IN (USER)` | 逐项 `intval` + 白名单 | 批量参数化较复杂，需仔细审查 |
| 表名/列名 `ORDER BY USER` | 白名单 | 参数化不支持表名/列名 |
| LIKE 子句 `LIKE '%USER%'` | 参数化 + `%` `_` 转义 | 仅防 SQLi，模糊查询性能需另考虑 |

### 2.3 Path Traversal 上下文矩阵

| 使用方式 | 有效净化 | 说明 |
|---------|---------|------|
| 文件名（basename 场景）| `basename()` | 只取文件名，不允许路径分隔符 |
| 完整路径 | `realpath()` + `strpos($path, $base) === 0` | 必须两步都做 |
| URL 路径拼接 | URL 解码后再 `realpath` | 先解码再校验，防编码绕过 |
| 压缩包解压路径 | zip entry 名逐项 `realpath` 校验 | 常见 Zip Slip 场景 |

---

## 3. 旁路模式详细分析

### 3.1 编码绕过

```
场景: WAF/过滤器在编码前检查，sink 在解码后使用
示例: filter(urlencode($_GET['path'])) → decode → file_get_contents
检测: 确认过滤执行时机 vs 解码时机
```

### 3.2 双重编码

```
%2527 → URL解码 → %27 → 再次解码 → '
适用: 多层代理/框架自动解码两次
检测: 追踪请求经过几次 URL 解码
```

### 3.3 Unicode / 宽字节

```
PHP + GBK: addslashes 后 %bf%27 → 宽字节吃掉反斜杠 → '
全角字符: ＜ (U+FF1C) → 某些过滤器不识别，渲染时等价于 <
检测: 确认字符集处理是否贯穿整个输入→输出链
```

### 3.4 大小写绕过

```
过滤: str_replace('<script>', '', $input)
绕过: <Script> / <SCRIPT> / <scRipt>
检测: Read 过滤代码，确认是否 case-insensitive
```

### 3.5 数组输入绕过

```
过滤针对字符串: if (is_string($input)) htmlspecialchars($input)
绕过: input[]=<script> (数组类型，跳过字符串过滤)
检测: 确认类型检查是否覆盖数组输入
```

### 3.6 截断攻击

```
场景: 过滤后字符串被 substr/截断，净化结果被破坏
示例: sanitize("admin'--") → "admin'--" → substr(0,5) → "admin" (OK)
      但 sanitize("ad'min") → "ad\'min" → substr(0,5) → "ad\'" (反斜杠在末尾，未必安全)
```

### 3.7 多入口攻击（Phase 0D 模式 A+E）

```
当前路径有净化 → 检查同类 sink 的其他调用点是否也有净化
示例: upload_single() 净化了，upload_batch() 未净化
工具: Grep 同名 sink 函数的全部调用位置
```

### 3.8 Decode-After-WAF（反序列化特有）

```
unserialize(base64_decode($_POST['data']))
WAF 检查 base64 编码态 → 无法识别序列化特征
sink 解码后反序列化 → WAF 完全失效
适用: Discuz/PHPCMS/ThinkPHP/ECShop 同类变体
```

---

## 4. 净化位置评估

```
source → [净化A] → 存储 → [净化B] → sink
```

| 净化位置 | 风险 |
|---------|------|
| 在 source 后立即净化（写入前）| 若数据在新上下文使用，原净化可能失效（HTML编码数据用于SQL拼接）|
| 在 sink 前净化 | 最可靠，但需确认覆盖所有到达 sink 的路径 |
| 中间层净化 | 需追踪是否所有 source 都经过该中间层 |
| 多层净化 | 注意净化叠加可能造成双重编码，或某层净化被后续操作撤销 |

---

## 5. Sanitizer 推理输出模板

```
[SANITIZER_ANALYSIS] VULN-{编号}
净化函数:     {函数名} @ {文件:行}
类型匹配:     {匹配/不匹配} — {说明}
上下文覆盖:   {覆盖/未覆盖} — {当前输出上下文}
旁路风险:     {无/低/中/高} — {具体旁路模式}
推理结论:     无效净化(Confirmed) | 存在净化但可能绕过(Hypothesis) | 有效净化(FP)
```

---

## 6. 快速判断流程

```
发现净化函数
    ↓
Step1: 净化类型 vs 漏洞类型匹配？
    不匹配 → Confirmed（净化无效）
    匹配 ↓
Step2: 净化覆盖实际输出上下文？
    不覆盖 → Confirmed 或 Hypothesis（高置信度绕过）
    覆盖 ↓
Step3: 存在已知旁路模式？
    存在 → Hypothesis（标注旁路模式和置信度）
    不存在 → FP（净化有效，记录推理依据）
```
