package app.klevertopee.redissessionauth.service;

import app.klevertopee.redissessionauth.model.SessionData;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class SessionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final String SESSION_PREFIX = "session:";
    private static final long SESSION_TIMEOUT_MINUTES = 30;

    public SessionService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String createSession(String userId, String username, Set<String> roles) {
        String sessionId = UUID.randomUUID().toString();
        SessionData sessionData = new SessionData(userId, username, roles);
        String key = SESSION_PREFIX + sessionId;

        redisTemplate.opsForValue().set(key, sessionData, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES); // Set value and expiry in one operation

        return sessionId;
    }

    public boolean validateSession(String sessionId) {
        String key = SESSION_PREFIX + sessionId;
        SessionData sessionData = (SessionData) redisTemplate.opsForValue().get(key);

        if (sessionData == null || isSessionExpired(sessionData)) {
            deleteSession(sessionId); // Clean up
            return false;
        }

        return true;
    }

    private boolean isSessionExpired(SessionData sessionData) {
        // Assuming SessionData stores expiry time in milliseconds
        return sessionData.getExpiresAt() < System.currentTimeMillis();
    }

    public void deleteSession(String sessionId) {
        String key = SESSION_PREFIX + sessionId;
        redisTemplate.delete(key);
    }

    public void extendSession(String sessionId) {
        String key = SESSION_PREFIX + sessionId;
        SessionData sessionData = (SessionData) redisTemplate.opsForValue().get(key);

        if (sessionData != null) {
            redisTemplate.expire(key, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        }
    }
}
