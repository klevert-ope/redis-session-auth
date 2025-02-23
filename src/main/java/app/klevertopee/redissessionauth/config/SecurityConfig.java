package app.klevertopee.redissessionauth.config;

import app.klevertopee.redissessionauth.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Configuration class for Spring Security.
 * This class defines security rules, password encoding, and custom filters.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SessionService sessionService;

    /**
     * Configures the security filter chain.
     *
     * @param http The HttpSecurity object to configure.
     * @return The configured SecurityFilterChain.
     * @throws Exception If an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for stateless APIs
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/register", "/api/login").permitAll() // Public routes
                        .requestMatchers(HttpMethod.POST, "/api/admin/**").hasRole("ADMIN") // Role-based security for admin routes
                        .anyRequest().authenticated() // All other routes require authentication
                )
                .addFilterBefore(new SessionAuthenticationFilter(sessionService), UsernamePasswordAuthenticationFilter.class); // Add custom session filter

        return http.build();
    }

    /**
     * Provides a BCrypt password encoder bean.
     *
     * @return A BCryptPasswordEncoder instance.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Custom filter for session-based authentication.
     * This filter validates the session token for authenticated routes.
     */
    @Slf4j
    @Component
    @RequiredArgsConstructor
    static class SessionAuthenticationFilter extends OncePerRequestFilter {

        private final SessionService sessionService;

        /**
         * Filters incoming requests to validate session tokens.
         *
         * @param request     The incoming HTTP request.
         * @param response    The HTTP response.
         * @param filterChain The filter chain to continue processing the request.
         * @throws ServletException If a servlet-related error occurs.
         * @throws IOException      If an I/O error occurs.
         */
        @Override
        protected void doFilterInternal(@NotNull HttpServletRequest request,
                                        @org.jetbrains.annotations.NotNull @NotNull HttpServletResponse response,
                                        @org.jetbrains.annotations.NotNull @NotNull FilterChain filterChain) throws ServletException, IOException {
            String path = request.getRequestURI();

            // Skip authentication for public routes
            if (path.equals("/api/register") || path.equals("/api/login")) {
                log.debug("Skipping authentication for public route: {}", path);
                filterChain.doFilter(request, response);
                return;
            }

            // Check for Authorization header
            String authHeader = request.getHeader("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Unauthorized request - Missing or invalid Authorization header");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized - Missing or Invalid Authorization Header");
                return;
            }

            // Extract session token (remove "Bearer " prefix)
            String sessionToken = authHeader.substring(7);
            log.debug("Validating session token for request: {}", path);

            try {
                // Validate the session token
                if (sessionService.validateSession(sessionToken)) {
                    log.debug("Session token validated successfully for request: {}", path);
                    filterChain.doFilter(request, response); // Continue with the request
                } else {
                    log.warn("Unauthorized request - Invalid or expired session token");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Unauthorized - Invalid or Expired Session");
                }
            } catch (Exception e) {
                log.error("Error validating session token for request: {}", path, e);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Internal Server Error");
            }
        }
    }
}