# CI/CD 安全配置检查清单

## 文件发现
- [ ] 是否存在 `.github/workflows/*.yml`
- [ ] 是否存在 `.gitlab-ci.yml`
- [ ] 是否存在 `Jenkinsfile`
- [ ] 是否存在 `.circleci/config.yml`

## 脚本注入
- [ ] 是否在脚本中直接使用 `${{ github.event.* }}` 等不受信输入
- [ ] 是否对 PR 标题、分支名等进行了安全过滤
- [ ] 是否使用环境变量传递敏感数据而非直接拼接

## 密钥硬编码
- [ ] 是否在 YAML 文件中出现明文密码、token、SSH 密钥
- [ ] 是否使用 secrets 管理敏感信息（如 `${{ secrets.TOKEN }}`）

## 权限控制
- [ ] 是否设置了最小必要的 `permissions`
- [ ] 是否避免使用 `write-all` 或过高的 GITHUB_TOKEN 权限
- [ ] 第三方 Action 是否限制了权限（如 `actions/checkout` 无需写入）

## 第三方 Action 版本锁定
- [ ] 是否使用具体 commit hash（如 `actions/checkout@a81bbbf`）而非分支或 tag
- [ ] 是否定期审查第三方 Action 的更新

## 缓存安全
- [ ] 缓存路径是否可能被污染（如 `~/./npm`）
- [ ] 是否对缓存内容进行校验

## 其他
- [ ] 是否禁用自托管运行器的不安全功能
- [ ] 是否对构建产物进行安全扫描