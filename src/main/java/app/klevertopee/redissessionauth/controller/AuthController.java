package app.klevertopee.redissessionauth.controller;

import app.klevertopee.redissessionauth.model.User;
import app.klevertopee.redissessionauth.repository.UserRepository;
import app.klevertopee.redissessionauth.service.SessionService;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, SessionService sessionService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
    }

    @Setter
    @Getter
    public static class RegisterRequest {
        private String username;
        private String password;
    }

    @Setter
    @Getter
    public static class LoginRequest {
        private String username;
        private String password;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest registerRequest) {
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        }

        User user = new User(
                registerRequest.getUsername(),
                passwordEncoder.encode(registerRequest.getPassword()),
                Collections.singleton("ROLE_USER")
        );
        userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        Optional<User> userOpt = userRepository.findByUsername(loginRequest.getUsername());
        if (userOpt.isPresent() && passwordEncoder.matches(loginRequest.getPassword(), userOpt.get().getPassword())) {
            User user = userOpt.get();
            String sessionId = sessionService.createSession(user.getId().toString(), user.getUsername(), user.getRoles());
            return ResponseEntity.ok(sessionId);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, sessionService::deleteSession, "Logged out successfully");
    }

    @PostMapping("/end-session")
    public ResponseEntity<String> endSession(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, sessionService::deleteSession, "Session terminated due to security concerns");
    }

    @PostMapping("/protected-resource")
    public ResponseEntity<String> protectedResource(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, s -> {}, "Protected resource accessed");
    }

    @PostMapping("/extend-session")
    public ResponseEntity<String> extendSession(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, sessionService::extendSession, "Session extended");
    }

    private ResponseEntity<String> handleSessionRequest(
            String sessionId,
            java.util.function.Consumer<String> action,
            String successMessage
    ) {
        if (sessionId == null || sessionId.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Authorization header is missing or empty");
        }

        String token = sessionId;
        if (sessionId.startsWith("Bearer ")) {
            token = sessionId.substring(7); // Remove "Bearer " prefix
        }

        boolean sessionData = sessionService.validateSession(token);
        if (!sessionData) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired session");
        }

        action.accept(token);
        return ResponseEntity.ok(successMessage);
    }
}
