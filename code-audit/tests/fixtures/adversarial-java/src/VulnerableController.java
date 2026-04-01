// Adversarial Fixture - 测试对抗性编码 + 反射 + second-order taint
@RestController
public class VulnerableController {

    private CommentRepository repo; // 模拟 DB

    @PostMapping("/comment")
    public String submitComment(@RequestBody String comment) {
        // Round 1: 直接 sink（但被简单 sanitize）
        String sanitized = sanitizeHtml(comment);
        repo.save(sanitized); // 存入 DB

        // Round 2: Reflection + DI 绕过
        processWithReflection(sanitized);

        return "OK";
    }

    private void processWithReflection(String data) {
        try {
            // 对抗静态分析：反射调用 sink
            Class<?> clazz = Class.forName("com.example.SinkExecutor");
            Method m = clazz.getMethod("executeSQL", String.class);
            m.invoke(clazz.newInstance(), data); // 真实 sink
        } catch (Exception e) {}
    }

    // Round 3: Second-order + Async contamination
    @Async
    public void asyncPublishToCache(String data) {
        redisTemplate.opsForValue().set("cache:key", data); // 污染 Cache
    }

    private String sanitizeHtml(String input) { return input.replace("<", ""); } // 可绕过
}