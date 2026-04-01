# 二阶漏洞检测清单

> 配合 `references/core/second_order_taint.md` 使用。

## 存储点识别
- [ ] 数据库写入: `INSERT INTO` / `UPDATE` / ORM `.save()` / `.create()`
- [ ] 文件写入: `file_put_contents` / `fwrite` / `move_uploaded_file`
- [ ] 缓存写入: `redis->set` / `memcached->set` / Session 存储
- [ ] 日志写入: `error_log` / Monolog / logging.info

## 使用点识别（Sink 回读）
- [ ] 数据库读取后拼接 SQL 查询
- [ ] 数据库读取后直接输出 HTML（无转义）
- [ ] 文件名读取后拼接 shell 命令
- [ ] 缓存/Session 数据用于 eval/include/require
- [ ] 日志内容展示在管理界面

## Sanitizer 时机分析
- [ ] 写入时是否净化？净化方式是什么？
- [ ] 读取后使用时是否再次净化？
- [ ] 写入时的净化在读取后的新上下文中是否仍有效？
  （如：写入时 HTML 编码，读取后用于 SQL 拼接 → 净化失效）

## 跨请求验证
- [ ] 能否构造第一次请求写入 payload？
- [ ] 确认第二次请求的触发方式（用户操作/管理员操作/定时任务）
- [ ] 是否需要特定权限触发？
- [ ] 构造完整的跨请求 PoC

## 典型场景检查
- [ ] 用户名/昵称 → 后台展示（存储型 XSS）
- [ ] 用户注册信息 → 管理员查询 SQL 拼接（二次 SQLi）
- [ ] 上传文件名 → 后台处理命令拼接（二次命令注入）
- [ ] 订单备注 → 财务系统 CSV 导出（CSV 注入）
