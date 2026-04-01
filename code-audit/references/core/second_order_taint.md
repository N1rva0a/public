# Phase 5A: 二阶污点追踪 (Second-Order Taint Analysis)

> 目标：检测存储型XSS、二次SQL注入、二次命令注入等跨请求漏洞。
> 触发：deep 模式自动执行；规则9: 发现二阶污点路径时优先构造跨请求 PoC。

---

## 识别存储点

```bash
# PHP - 数据库写入
grep -rn "INSERT INTO\|UPDATE.*SET\|\$wpdb->insert\|\$db->query" --include="*.php" .

# PHP - 文件写入
grep -rn "file_put_contents\|fwrite\|move_uploaded_file\|copy(" --include="*.php" .

# PHP - 缓存/Session 写入
grep -rn "\$_SESSION\[.*\]\s*=\|redis->set\|memcached->set\|apc_store" --include="*.php" .

# Java - 数据库写入
grep -rn "\.save\|\.persist\|\.insert\|executeUpdate\|\.execute(" --include="*.java" .

# Python - ORM 写入
grep -rn "\.save()\|\.create(\|\.bulk_create\|session\.add" --include="*.py" .
```

---

## 识别后续使用点（Sink 回读）

重点检查从持久化存储读取数据后直接使用的场景：

| 存储类型 | 读取后的危险 Sink | 漏洞类型 |
|---------|----------------|---------|
| 数据库读取 → SQL 拼接 | `"SELECT ... WHERE " + $row['name']` | 二次 SQLi |
| 数据库读取 → HTML 输出 | `echo $row['comment']` (无转义) | 存储型 XSS |
| 数据库读取 → exec/system | `exec($row['command'])` | 二次命令注入 |
| 文件名 → shell 命令 | `exec("convert " . $filename)` | 命令注入 |
| 日志内容 → 管理界面展示 | `echo $log_content` | 存储型 XSS |
| Session 数据 → eval/include | `include($_SESSION['template'])` | 文件包含 |

---

## 跨请求污点追踪

```
请求1 (写入):  用户输入 → 存储点（数据库/文件/缓存）
请求2 (读取):  存储点 → 读取 → Sink（SQL/HTML/命令）

关键问题：
1. 写入时是否净化？（净化在写入时执行）
2. 读取后使用时是否再次净化？（净化在读取后执行）
3. 写入时的净化在新的输出上下文中是否仍然有效？
   示例：写入时 HTML 编码 → 读取后用于 SQL 拼接 → HTML 编码无法阻止 SQLi
```

---

## Sanitizer 时机陷阱（v4.0 补充）

```
写入时净化的失效场景：
  用户输入 → htmlspecialchars() → 存储为 HTML 编码字符串
  → 读取后用于 SQL 查询拼接
  → HTML 编码不阻止 SQL 注入 → 漏洞成立

读取时净化的覆盖问题：
  用户输入 → 原始存储
  → 读取后用于 HTML 输出，但输出函数 A 有净化
  → 读取后用于 SQL 拼接，输出函数 B 无净化
  → 函数 B 存在漏洞
```

---

## 跨请求 PoC 构造模板

```
[SECOND_ORDER_POC]
漏洞类型: 二次 SQL 注入
写入端点: POST /api/user/register  参数: username
存储位置: users 表 username 字段
触发端点: GET /admin/search?q=  (管理员搜索，从 username 列拼接查询)

步骤1 (写入 payload):
  POST /api/user/register
  {"username": "' UNION SELECT password FROM admin--", "password": "x"}

步骤2 (触发):
  GET /admin/search?q=  (管理员执行任意搜索触发)
  或: 等待定时任务/管理员操作读取该数据

预期结果: admin 表密码泄露
验证状态: [待验证/已验证]
```

---

## 输出格式

```
[SECOND_ORDER]
潜在二阶漏洞 {N} 个:

SORD-001: 二次 SQL 注入
  写入点: {文件:行} - INSERT INTO {表} ({字段}) VALUES ('{用户输入}')
  使用点: {文件:行} - SELECT ... WHERE {字段} LIKE '%{从DB读取}%'
  净化分析: 写入时 addslashes（有效），读取后直接拼接（无净化）
  跨请求 PoC: [见上方模板]
  置信度: Confirmed / Hypothesis
```
