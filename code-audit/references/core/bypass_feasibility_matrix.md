# Bypass Feasibility Matrix 模板

当评估 E4（defense assessment）时，必须使用此标准化矩阵：

| Bypass 向量                  | 可行性 (High/Med/Low) | 具体证据/代码路径/行号                  | 当前防御是否可被绕过 | 备注 |
|-----------------------------|-----------------------|----------------------------------------|---------------------|------|
| Framework 配置/注解覆盖      | High                  | application.yml:42 或 @Value 注入      | 是                  | 可通过自定义 Bean 完全覆盖 |
| Reflection / DI 注入         | Med                   | UserService.java:145 Class.forName()   | 否                  | 反射路径被权限检查阻断 |
| Second-order taint (DB→Cache) | High                 | Comment → ArticleController            | 是                  | 无二次 sanitization |
| Race condition / TOCTOU      | Med                   | concurrent requests on /order endpoint | 是                  | 缺少锁 |
| Version boundary             | Low                   | library 1.2.3（已知 CVE）             | 否                  | 已升级到安全版本 |

**最终结论**：本 finding 的 defense 是否充分？ **[充分 / 部分 / 否，可被绕过]**