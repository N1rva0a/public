# 供应链安全审计详细指南

> Phase -1 执行参考。目标：在代码审计前评估第三方依赖风险。

---

## 工具选择

| 工具 | 语言 | 用途 |
|------|------|------|
| OWASP Dependency-Check | Java/.NET/Python/Ruby/PHP | CVE 扫描，支持多语言 |
| Snyk | 多语言 + 容器 | 商业，CI/CD 集成友好 |
| npm audit / yarn audit | Node.js | 内置，无需安装 |
| pip-audit | Python | PyPA 官方工具 |
| cargo audit | Rust | rustsec.org 数据库 |
| bundler-audit | Ruby | rubysec.com 数据库 |
| ossindex | 多语言 | Sonatype OSS Index |

---

## 执行流程

```bash
# 1. 自动扫描
dependency-check --scan . --format JSON --out report/
npm audit --json > npm_audit.json 2>/dev/null
pip-audit --format json > pip_audit.json 2>/dev/null

# 2. 提取高危项（Critical/High）
cat report/*.json | jq '.dependencies[].vulnerabilities[] | select(.severity == "CRITICAL" or .severity == "HIGH")'

# 3. 依赖混淆检测（Node.js）
# 检查 package.json 中无 @scope 前缀的私有包是否在 npmjs.com 存在同名公共包
cat package.json | jq '.dependencies | keys[]' | grep -v '^"@' | while read pkg; do
  curl -s "https://registry.npmjs.org/${pkg//\"/}" | jq -r '.name // "NOT_FOUND"'
done
```

---

## 依赖混淆防御标准

1. 私有包必须有 scope（`@company/package-name`）
2. 配置私有仓库优先（`.npmrc` 中 `registry=https://private.registry`）
3. 使用 `npm pack` + 哈希校验防止篡改
4. CI/CD 中锁定 `package-lock.json` / `composer.lock` 提交

---

## 恶意包响应流程

```
发现可疑包 →
1. 立即隔离：yarn remove / pip uninstall
2. 检查 install 脚本是否已执行（查看系统日志/网络请求）
3. 评估数据泄露范围（env 变量、文件读写权限）
4. 替换为可信版本并 audit fix
```

---

## 供应链攻击历史案例

| 事件 | 包名 | 攻击手段 | 影响 |
|------|------|---------|------|
| event-stream (2018) | event-stream | 账户劫持 → 恶意依赖注入 | 比特币钱包窃取 |
| ua-parser-js (2021) | ua-parser-js | 账户劫持 → 恶意 postinstall | 加密货币挖矿 |
| codecov (2021) | codecov | 修改安装脚本 | CI 环境变量泄露 |
| SolarWinds (2020) | Orion | 构建系统入侵 | 供应链后门 |
| node-ipc (2022) | node-ipc | 故意注入 | 据地理位置破坏文件 |

---

## 与 Phase 5B 联动

发现以下 CVE 类型时，**强制触发 Phase 5B Gadget 枚举**：
- Java 反序列化相关（commons-collections/spring/groovy）
- PHP 反序列化（任意版本）
- Python pickle/PyYAML 不安全加载
- Node.js 原型链污染（lodash merge/deepmerge）
