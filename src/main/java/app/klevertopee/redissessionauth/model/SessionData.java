package app.klevertopee.redissessionauth.model;

import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.util.Set;

/**
 * Represents session data stored in Redis.
 * This class is used to store user session information, including user details and session expiration.
 */
@Data
public class SessionData implements Serializable {

    /**
     * A unique identifier for serialization.
     * This ensures compatibility during deserialization.
     */
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * The default session timeout in minutes.
     * This value aligns with the session timeout defined in the SessionService.
     */
    private static final long DEFAULT_SESSION_TIMEOUT_MINUTES = 30;

    /**
     * The unique identifier of the user associated with this session.
     */
    private String userId;

    /**
     * The username of the user associated with this session.
     */
    private String username;

    /**
     * The roles assigned to the user associated with this session.
     */
    private Set<String> roles;

    /**
     * The timestamp (in milliseconds) when the session was created.
     */
    private long createdAt;

    /**
     * The timestamp (in milliseconds) when the session will expire.
     */
    private long expiresAt;

    /**
     * Constructs a new SessionData object with the specified user details.
     *
     * @param userId   The unique identifier of the user.
     * @param username The username of the user.
     * @param roles    The roles assigned to the user.
     */
    public SessionData(String userId, String username, Set<String> roles) {
        this.userId = userId;
        this.username = username;
        this.roles = roles;
        this.createdAt = System.currentTimeMillis();
        this.expiresAt = this.createdAt + (DEFAULT_SESSION_TIMEOUT_MINUTES * 60 * 1000); // 30 minutes default expiration
    }

    /**
     * Checks if the session is expired based on the current system time.
     *
     * @return true if the session is expired, false otherwise.
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAt;
    }
}