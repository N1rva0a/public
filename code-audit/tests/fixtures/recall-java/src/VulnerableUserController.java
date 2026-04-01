package fixtures.recall;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class VulnerableUserController {
    private final Connection connection;

    public VulnerableUserController(Connection connection) {
        this.connection = connection;
    }

    public ResultSet searchUser(String username) throws SQLException {
        Statement statement = connection.createStatement();
        String sql = "SELECT id, username FROM users WHERE username = '" + username + "'";
        return statement.executeQuery(sql);
    }
}
