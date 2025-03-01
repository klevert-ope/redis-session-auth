package app.klevertopee.redissessionauth.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

/**
 * Represents a user entity in the application.
 * This class is mapped to the "users" table in the database.
 */
@Setter
@Getter
@Entity
@Table(name = "users")
public class User {

    /**
     * The unique identifier for the user.
     * This field is auto-generated by the database.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The username of the user.
     * This field is required, must be unique, and must be between 3 and 50 characters.
     */
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Column(nullable = false, unique = true)
    private String username;

    /**
     * The password of the user.
     * This field is required and must be between 8 and 100 characters.
     * The password should be stored in a hashed format for security.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    @Column(nullable = false)
    private String password;

    /**
     * The email address of the user.
     * This field is required, must be unique, and must be a valid email format.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * The roles assigned to the user.
     * This is a collection of roles stored in a separate table "user_roles".
     * Roles are eagerly fetched to ensure they are available when the user is loaded.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles;

    /**
     * Default constructor required by JPA.
     */
    public User() {}

    /**
     * Parameterized constructor to create a new user with the specified details.
     *
     * @param username The username of the user.
     * @param password The password of the user.
     * @param email    The email address of the user.
     * @param roles    The roles assigned to the user.
     */
    public User(String username, String password, String email, Set<String> roles) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.roles = roles;
    }
}