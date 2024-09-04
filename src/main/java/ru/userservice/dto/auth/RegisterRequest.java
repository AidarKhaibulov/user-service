package ru.userservice.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import ru.userservice.enums.Role;


/**
 * Represents a request to register a new user.
 * <p>
 * This class contains the necessary information for user registration, including username, email address,
 * password, and user role. Validation annotations ensure that the input data meets the required constraints.
 * </p>
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    @Schema(description = "Username", example = "Jon")
    @Size(min = 5, max = 50, message = "Username must be between 5 and 50 characters long")
    @NotBlank(message = "Username cannot be blank")
    private String username;

    @Schema(description = "Email address", example = "jondoe@gmail.com")
    @Size(min = 5, max = 255, message = "Email address must be between 5 and 255 characters long")
    @NotBlank(message = "Email address cannot be blank")
    @Email(message = "Email address must be in the format user@example.com")
    private String email;

    @Schema(description = "Password", example = "my_1secret1_password")
    @Size(max = 255, message = "Password length must not exceed 255 characters")
    @Size(min = 8, message = "Password length must be at least 8 characters")
    private String password;

    private Role role;

}