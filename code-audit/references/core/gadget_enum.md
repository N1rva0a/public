# Phase 5B: Gadget 链枚举 (三轨并行)

> 目标：针对反序列化漏洞，系统搜索可利用 gadget 链。
> 触发：deep 模式自动执行；规则1: Phase -1 发现高危反序列化库时强制执行。

---

## 反序列化入口识别

**PHP:**
```bash
grep -rn "unserialize(" --include="*.php" .
grep -rn "unserialize(base64_decode\|unserialize(urldecode\|unserialize(gzinflate" --include="*.php" .
```

**Java:**
```bash
grep -rn "ObjectInputStream\|readObject\|fromXML\|Yaml.load\|JSON.parseObject" --include="*.java" .
grep -rn "XStream\|Kryo\|Hessian\|JDK_SERIALIZATION" --include="*.java" .
```

**Python:**
```bash
grep -rn "pickle.loads\|pickle.load\|yaml.load\|marshal.loads\|jsonpickle.decode" --include="*.py" .
```

---

## 三轨并行审计

### 轨道1: 类加载时序分析

回溯 `unserialize`/`readObject` 前的 `require`/`import` 链，建立 T时刻可用类集合。

```
PHP 示例:
1. 找到 unserialize($_COOKIE['data']) 所在文件
2. 向上追踪该文件的 require/include 链
3. 列出所有已加载类 → 建立 gadget 候选集

Java 示例:
1. 找到 ObjectInputStream.readObject() 所在位置
2. 检查该时刻 classpath 中的所有 jar
3. 使用 gadgetinspector 扫描完整 classpath
```

**集合为空 → 强制降级为 Low（无可用 gadget 链）**

### 轨道2: 过滤器旁路检查

检查反序列化结果合并进超全局变量时，WAF/filterData 是否覆盖该数据路径。

```
重点检查模式:
unserialize(decode_fn($_INPUT))
→ WAF 检查编码态（看不到序列化特征）
→ sink 使用解码后值（WAF 完全失效）

Decode-After-WAF 变体（Discuz/PHPCMS/ThinkPHP/ECShop）:
- base64_decode → unserialize
- urldecode → unserialize
- gzinflate → unserialize
- hex2bin → unserialize
```

**判定：若 WAF 在解码前检查 → 过滤器无效 → 提升为 Confirmed**

### 轨道3: 已知链匹配 + PHP 内置类

**Java 已知链（ysoserial）:**

| 链名 | 所需依赖 | 效果 |
|------|---------|------|
| CommonsCollections1-7 | commons-collections 3.x | RCE |
| Spring1/Spring2 | spring-core, spring-aop | RCE |
| Groovy1 | groovy | RCE |
| BeanShell1 | bsh | RCE |
| Clojure | clojure | RCE |
| C3P0 | c3p0 | JNDI |
| JRMPClient | 通用 | JNDI |

**PHP 已知链（phpggc）:**
```bash
phpggc --list | grep {框架名}  # Laravel/Symfony/Monolog/Guzzle/etc
phpggc {链名} exec 'id' -b     # 生成 base64 payload
```

**PHP 内置类（类集合为空时降级评估）:**

| 类 | 魔术方法 | 可利用场景 |
|----|---------|-----------|
| `SplFileObject` | `__toString` | 文件读取 |
| `SimpleXMLElement` | `__toString` | XXE（PHP < 8） |
| `PDO` | `__destruct` | 数据库连接（需凭据）|
| `SplStack` | `__destruct` | 间接利用 |

**PHP 5.x 内置类 → 通常降级为 Low**

---

## 自定义链构造

若已知链不存在，分析项目自定义类：

```bash
# PHP: 查找魔术方法
grep -rn "__wakeup\|__destruct\|__toString\|__call\|__get\|__set" --include="*.php" .

# Java: 查找危险的 readObject/readResolve
grep -rn "readObject\|readResolve\|finalize" --include="*.java" .
```

构造路径：魔术方法 → 中间调用 → 危险函数（eval/exec/file_put_contents/include）

---

## 输出格式

```
[PHASE_5B_SUMMARY]
轨道1 - 可用类集合: {N 个类} | 关键类: {列表}
轨道2 - 过滤器状态: {有效/WAF绕过/无过滤}
轨道3 - 已知链匹配: {链名 | 所需依赖 | 依赖是否存在}
         PHP内置类: {适用/不适用(类集合非空)}

综合最高威胁路径:
  链: {CommonsCollections1 / 自定义链 / 内置类}
  利用效果: {RCE/文件读写/JNDI}
  置信度: {Confirmed/Hypothesis}
  PoC 工具: {ysoserial/phpggc/手工构造}
```
