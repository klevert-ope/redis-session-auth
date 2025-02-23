package app.klevertopee.redissessionauth.service;

import app.klevertopee.redissessionauth.model.SessionData;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final String SESSION_PREFIX = "session:";
    private static final long SESSION_TIMEOUT_MINUTES = 30; // Session timeout in minutes

    // In-memory cache for session validation
    private final Cache<String, Boolean> sessionValidationCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES) // Cache entries expire after 5 minutes
            .maximumSize(10_000) // Maximum cache size
            .build();

    /**
     * Creates a new session for the given user and stores it in Redis.
     *
     * @param userId   The ID of the user.
     * @param username The username of the user.
     * @param roles    The roles associated with the user.
     * @return The generated session ID.
     * @throws RuntimeException If the session creation fails.
     */
    public String createSession(String userId, String username, Set<String> roles) {
        try {
            String sessionId = UUID.randomUUID().toString();
            SessionData sessionData = new SessionData(userId, username, roles);
            String key = SESSION_PREFIX + sessionId;

            // Store the session in Redis with a timeout
            redisTemplate.opsForValue().set(key, sessionData, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);

            log.info("Session created successfully for user: {}", username);
            return sessionId;
        } catch (Exception e) {
            log.error("Failed to create session for user: {}", username, e);
            throw new RuntimeException("Failed to create session", e);
        }
    }

    /**
     * Validates a session by checking if it exists and is not expired.
     * Uses an in-memory cache to reduce Redis calls.
     *
     * @param sessionId The session ID to validate.
     * @return true if the session is valid, false otherwise.
     * @throws RuntimeException If the session validation fails.
     */
    public boolean validateSession(String sessionId) {
        // Check the in-memory cache first
        Boolean cachedValidation = sessionValidationCache.getIfPresent(sessionId);
        if (cachedValidation != null) {
            log.debug("Session validation result retrieved from cache for sessionId: {}", sessionId);
            return cachedValidation;
        }

        try {
            String key = SESSION_PREFIX + sessionId;
            SessionData sessionData = (SessionData) redisTemplate.opsForValue().get(key);

            if (sessionData == null || sessionData.isExpired()) {
                deleteSession(sessionId); // Clean up expired or invalid session
                log.warn("Session validation failed for sessionId: {}", sessionId);
                sessionValidationCache.put(sessionId, false); // Cache the result
                return false;
            }

            sessionValidationCache.put(sessionId, true); // Cache the result
            return true;
        } catch (Exception e) {
            log.error("Failed to validate session: {}", sessionId, e);
            throw new RuntimeException("Failed to validate session", e);
        }
    }

    /**
     * Deletes a session from Redis and invalidates the cache entry.
     *
     * @param sessionId The session ID to delete.
     * @throws RuntimeException If the session deletion fails.
     */
    public void deleteSession(String sessionId) {
        try {
            String key = SESSION_PREFIX + sessionId;
            redisTemplate.delete(key);
            sessionValidationCache.invalidate(sessionId); // Invalidate the cache entry
            log.info("Session deleted successfully for sessionId: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to delete session: {}", sessionId, e);
            throw new RuntimeException("Failed to delete session", e);
        }
    }

    /**
     * Extends the expiration time of a session and updates the cache.
     *
     * @param sessionId The session ID to extend.
     * @throws RuntimeException If the session extension fails.
     */
    public void extendSession(String sessionId) {
        try {
            String key = SESSION_PREFIX + sessionId;
            SessionData sessionData = (SessionData) redisTemplate.opsForValue().get(key);

            if (sessionData != null) {
                // Extend the session by resetting the expiration time
                redisTemplate.expire(key, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                sessionValidationCache.put(sessionId, true); // Update the cache
                log.info("Session extended successfully for sessionId: {}", sessionId);
            } else {
                sessionValidationCache.invalidate(sessionId); // Invalidate the cache entry
                log.warn("Session not found for extension: {}", sessionId);
            }
        } catch (Exception e) {
            log.error("Failed to extend session: {}", sessionId, e);
            throw new RuntimeException("Failed to extend session", e);
        }
    }
}