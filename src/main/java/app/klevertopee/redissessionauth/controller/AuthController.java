package app.klevertopee.redissessionauth.controller;

import app.klevertopee.redissessionauth.model.User;
import app.klevertopee.redissessionauth.repository.UserRepository;
import app.klevertopee.redissessionauth.service.SessionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;

    // DTOs for request/response
    @Data
    public static class RegisterRequest {
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        private String username;

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
        private String password;

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        private String email;
    }

    @Data
    public static class LoginRequest {
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        private String email;

        @NotBlank(message = "Password is required")
        private String password;
    }

    @Data
    public static class AuthResponse {
        private String message;
        private String sessionId;

        public AuthResponse(String message, String sessionId) {
            this.message = message;
            this.sessionId = sessionId;
        }

        public AuthResponse(String message) {
            this.message = message;
        }
    }

    /**
     * Registers a new user.
     *
     * @param registerRequest The registration request containing username, password, and email.
     * @return A response indicating success or failure.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        // Check if username already exists
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new AuthResponse("Username already exists"));
        }

        // Check if email already exists
        if (userRepository.findByEmail(registerRequest.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new AuthResponse("Email already exists"));
        }

        // Create and save the new user
        User user = new User(
                registerRequest.getUsername(),
                passwordEncoder.encode(registerRequest.getPassword()),
                registerRequest.getEmail(),
                Collections.singleton("ROLE_USER")
        );
        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new AuthResponse("User registered successfully"));
    }

    /**
     * Logs in a user using their email and creates a session.
     *
     * @param loginRequest The login request containing email and password.
     * @return A response containing the session ID or an error message.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        // Find the user by email
        Optional<User> userOpt = userRepository.findByEmail(loginRequest.getEmail());
        if (userOpt.isEmpty() || !passwordEncoder.matches(loginRequest.getPassword(), userOpt.get().getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse("Invalid email or password"));
        }

        // Create a session for the user
        User user = userOpt.get();
        String sessionId = sessionService.createSession(user.getId().toString(), user.getUsername(), user.getRoles());

        return ResponseEntity.ok(new AuthResponse("Login successful", sessionId));
    }

    /**
     * Logs out a user by deleting their session.
     *
     * @param sessionId The session ID from the Authorization header.
     * @return A response indicating success or failure.
     */
    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, sessionService::deleteSession, "Logged out successfully");
    }

    /**
     * Ends a session (similar to logout but with a different message).
     *
     * @param sessionId The session ID from the Authorization header.
     * @return A response indicating success or failure.
     */
    @PostMapping("/end-session")
    public ResponseEntity<AuthResponse> endSession(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, sessionService::deleteSession, "Session terminated due to security concerns");
    }

    /**
     * Accesses a protected resource after validating the session.
     *
     * @param sessionId The session ID from the Authorization header.
     * @return A response indicating success or failure.
     */
    @PostMapping("/protected-resource")
    public ResponseEntity<AuthResponse> protectedResource(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, s -> {}, "Protected resource accessed");
    }

    /**
     * Extends the expiration time of a session.
     *
     * @param sessionId The session ID from the Authorization header.
     * @return A response indicating success or failure.
     */
    @PostMapping("/extend-session")
    public ResponseEntity<AuthResponse> extendSession(@RequestHeader("Authorization") String sessionId) {
        return handleSessionRequest(sessionId, sessionService::extendSession, "Session extended");
    }

    /**
     * Handles session-related requests by validating the session and performing the given action.
     *
     * @param sessionId      The session ID from the Authorization header.
     * @param action         The action to perform if the session is valid.
     * @param successMessage The message to return if the action is successful.
     * @return A response indicating success or failure.
     */
    private ResponseEntity<AuthResponse> handleSessionRequest(
            String sessionId,
            java.util.function.Consumer<String> action,
            String successMessage
    ) {
        if (sessionId == null || sessionId.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthResponse("Authorization header is missing or empty"));
        }

        String token = sessionId.startsWith("Bearer ") ? sessionId.substring(7) : sessionId; // Remove "Bearer " prefix

        if (!sessionService.validateSession(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse("Invalid or expired session"));
        }

        action.accept(token);
        return ResponseEntity.ok(new AuthResponse(successMessage));
    }
}