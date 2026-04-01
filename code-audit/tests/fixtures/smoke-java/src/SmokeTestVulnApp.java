package fixtures.smoke;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SmokeTestVulnApp {
    private static final String API_KEY = "hardcoded-demo-key";

    private final Connection connection;
    private final Path baseDir;

    public SmokeTestVulnApp(Connection connection, Path baseDir) {
        this.connection = connection;
        this.baseDir = baseDir;
    }

    // Missing auth guard on an admin-style action.
    public String adminRun(String command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("cmd", "/c", command).start();
        return "exit=" + process.waitFor();
    }

    public ResultSet searchUser(String username) throws SQLException {
        Statement statement = connection.createStatement();
        String sql = "SELECT id, username FROM users WHERE username = '" + username + "'";
        return statement.executeQuery(sql);
    }

    public byte[] downloadFile(String filename) throws IOException {
        return Files.readAllBytes(baseDir.resolve(filename));
    }

    public Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes));
        return input.readObject();
    }

    public String apiKey() {
        return API_KEY;
    }
}
