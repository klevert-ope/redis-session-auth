package app.klevertopee.redissessionauth.repository;

import app.klevertopee.redissessionauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Finds a user by their username.
     *
     * @param username The username to search for.
     * @return An Optional containing the user if found, otherwise empty.
     */
    Optional<User> findByUsername(String username);

    /**
     * Finds a user by their email.
     *
     * @param email The email to search for.
     * @return An Optional containing the user if found, otherwise empty.
     */
    Optional<User> findByEmail(String email);

    /**
     * Finds a user by either their username or email.
     *
     * @param username The username to search for.
     * @param email    The email to search for.
     * @return An Optional containing the user if found, otherwise empty.
     */
    Optional<User> findByUsernameOrEmail(String username, String email);
}