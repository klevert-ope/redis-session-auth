package app.klevertopee.redissessionauth.model;

import lombok.Data;
import java.io.Serializable;
import java.util.Set;

@Data
public class SessionData implements Serializable {
    private String userId;
    private String username;
    private Set<String> roles;
    private long createdAt;
    private long expiresAt;

    public SessionData(String userId, String username, Set<String> roles) {
        this.userId = userId;
        this.username = username;
        this.roles = roles;
        this.createdAt = System.currentTimeMillis();
        this.expiresAt = this.createdAt + (30 * 60 * 1000); // 30 minutes default expiration
    }
}