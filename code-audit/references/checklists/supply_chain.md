# 供应链安全检查清单

> 配合 `references/core/supply_chain.md` 使用。Phase -1 专用，优先于代码审计执行。

## 依赖文件发现
- [ ] `composer.lock` (PHP)
- [ ] `package-lock.json` / `yarn.lock` (Node.js)
- [ ] `go.sum` / `go.mod` (Go)
- [ ] `pom.xml` / `build.gradle` (Java)
- [ ] `requirements.txt` / `Pipfile.lock` (Python)
- [ ] `Gemfile.lock` (Ruby) / `Cargo.lock` (Rust)

## CVE 扫描
- [ ] 运行 OWASP Dependency-Check 或 Snyk 扫描
- [ ] `npm audit` / `pip-audit` / `cargo audit`（语言原生工具）
- [ ] 记录所有 Critical/High 级别 CVE 及修复版本
- [ ] 标注哪些 CVE 涉及反序列化（触发 Phase 5B 强制执行）

## 依赖混淆检测
- [ ] 检查私有包名是否在公共仓库（npm/PyPI）中存在同名包
- [ ] 私有包是否配置了作用域（如 `@company/package`）
- [ ] `.npmrc` / `pip.conf` 是否配置了私有仓库优先

## 恶意包检测
- [ ] 使用 `ossindex` 或 Socket.dev 检测已知恶意包
- [ ] 检查近期新增依赖是否有可疑 install 脚本（`postinstall`/`preinstall`）
- [ ] 检查依赖发布者账户是否异常（账户劫持）

## 输出格式
```
[SUPPLY_CHAIN]
高风险依赖: {依赖名 | 版本 | CVE | 严重度 | 修复版本}
依赖混淆风险: {是/否, 说明}
恶意包检测: {无异常 / 发现: ...}
反序列化相关CVE: {是/否 → 是则触发 Phase 5B}
```
