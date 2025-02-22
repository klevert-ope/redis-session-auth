package app.klevertopee.redissessionauth.config;

import app.klevertopee.redissessionauth.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
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

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final SessionService sessionService;

    public SecurityConfig(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/register", "/api/login").permitAll()  // Public routes
                        .requestMatchers(HttpMethod.POST, "/api/admin/**").hasRole("ADMIN") // Role-based security
                        .anyRequest().authenticated() // All other routes require authentication
                )
                .addFilterBefore(new SessionAuthenticationFilter(sessionService), UsernamePasswordAuthenticationFilter.class);  // Session filter for authenticated routes

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Component
    static class SessionAuthenticationFilter extends OncePerRequestFilter {

        private final SessionService sessionService;

        public SessionAuthenticationFilter(SessionService sessionService) {
            this.sessionService = sessionService;
        }

        @Override
        protected void doFilterInternal(@NotNull HttpServletRequest request,
                                        @NotNull HttpServletResponse response,
                                        @NotNull FilterChain filterChain) throws ServletException, IOException {
            String path = request.getRequestURI();

            // Skip authentication for registration and login routes
            if (path.equals("/api/register") || path.equals("/api/login")) {
                filterChain.doFilter(request, response);
                return;
            }

            // Check for Authorization header to validate session
            String authHeader = request.getHeader("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized - Missing or Invalid Authorization Header");
                return;
            }

            // Extract token (Remove "Bearer " prefix)
            String sessionToken = authHeader.substring(7);

            try {
                if (sessionService.validateSession(sessionToken)) {
                    filterChain.doFilter(request, response);  // Continue with the request if session is valid
                } else {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Unauthorized - Invalid or Expired Session");
                }
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Internal Server Error");
            }
        }
    }
}
