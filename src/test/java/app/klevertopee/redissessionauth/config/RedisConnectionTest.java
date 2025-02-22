package app.klevertopee.redissessionauth.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class RedisConnectionTest {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Test
    public void testRedisConnection() {
        // Try to set a value to Redis
        redisTemplate.opsForValue().set("testKey", "testValue");

        // Retrieve the value to check the connection
        String value = (String) redisTemplate.opsForValue().get("testKey");

        // Assert that the value is not null, meaning the connection works
        assertNotNull(value);
        System.out.println("Successfully connected to Redis. Value: " + value);

        // Optionally assert the correct value was stored
        assertEquals("testValue", value);
    }
}