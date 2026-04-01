package fixtures.precision;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class SafeSearchController {
    public enum SortField {
        ID,
        CREATED_AT
    }

    private final Connection connection;

    public SafeSearchController(Connection connection) {
        this.connection = connection;
    }

    public PreparedStatement buildQuery(String username, SortField sortField) throws SQLException {
        String orderByColumn = switch (sortField) {
            case ID -> "id";
            case CREATED_AT -> "created_at";
        };

        String sql = "SELECT id, username FROM users WHERE username = ? ORDER BY " + orderByColumn;
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.setString(1, username);
        return statement;
    }
}
