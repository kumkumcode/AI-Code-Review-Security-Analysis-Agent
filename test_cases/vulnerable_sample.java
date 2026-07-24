import java.sql.*;

public class SecuritySample {
    // SECURITY RISK: Hardcoded API Secret Key
    private static final String AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";

    public void getUserData(String userId) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "");
            Statement stmt = conn.createStatement();
            // SECURITY RISK: Unparameterized SQL String Addition
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            ResultSet rs = stmt.executeQuery(query);
        } catch (Exception e) {
            // CODE SMELL: Empty Exception Handling Block
        }
    }

    public void complexMethod(int x) {
        // CODE SMELL: High Cognitive Complexity (Deep Nesting)
        if (x > 0) {
            if (x < 10) {
                if (x % 2 == 0) {
                    System.out.println("Even");
                }
            }
        }
    }
}