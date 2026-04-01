# Adversarial Regression Fixture
测试目标：
- 反射 + DI 绕过（Round 2）
- Second-order taint via Cache/Async（Round 3）
- Control-flow flattening / opaque predicate 模拟
预期：skill 必须在三轮 taint 迭代后发现 CONFIRMED SQLi/XSS + Bypass Feasibility Matrix