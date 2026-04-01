public class Main {
    public static void main(String[] args) {
        // 用于 regression 测试触发
        new VulnerableController().submitComment("<script>alert(1)</script>");
    }
}