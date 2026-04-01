# CI/CD 管道安全配置指南

## 工作流注入防护
- 避免直接拼接不受信输入到脚本中
- 使用 GitHub 提供的 `github.context` 时进行正则过滤
- 对 PR 来自 fork 的仓库应限制权限（如 `pull_request_target` 需谨慎）

## 密钥管理
- 所有敏感信息必须使用 CI 平台的 secrets 存储
- 避免在日志中打印 secrets（设置 `set +x` 或 masking）
- 定期轮换密钥

## 最小权限原则
- 设置 `permissions: read-all` 或按需配置
- 对第三方 Action 设置 `permissions: {}` 限制其默认权限

## 第三方 Action 审查
- 优先使用官方或经过验证的 Action
- 锁定到具体 commit hash，避免被篡改
- 定期审查使用的 Action 版本更新

## 自托管运行器安全
- 避免在公共仓库中使用自托管运行器（可被 PR 注入）
- 若必须使用，确保运行器隔离、环境干净、无持久化数据

## 缓存安全
- 使用缓存 key 包含分支信息，避免跨分支污染
- 对缓存内容进行完整性校验（如 `hashFiles`）

## 镜像构建与部署
- 使用非 root 用户运行容器
- 扫描镜像漏洞（Trivy、Clair）
- 签名镜像确保完整性