package ru.userservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.userservice.repositories.UserRepository;

/**
 * Configuration class for Spring Security authentication.
 * <p>
 * This class defines the beans required for user authentication, including the user details service,
 * authentication provider, authentication manager, and password encoder.
 * </p>
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;

    /**
     * Provides a {@link UserDetailsService} bean.
     * <p>
     * This service is used by Spring Security to load user-specific data during authentication.
     * It retrieves a user by email from the {@link UserRepository}.
     * </p>
     *
     * @return a {@link UserDetailsService} implementation
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return email -> repository.findByUsername(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    /**
     * Provides an {@link AuthenticationProvider} bean.
     * <p>
     * This provider is used by Spring Security to authenticate a user. It uses the {@link UserDetailsService}
     * and {@link PasswordEncoder} to verify user credentials.
     * </p>
     *
     * @return an {@link AuthenticationProvider} implementation
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Provides an {@link AuthenticationManager} bean.
     * <p>
     * This manager is used to handle authentication requests. It is created from the {@link AuthenticationConfiguration}.
     * </p>
     *
     * @param config the {@link AuthenticationConfiguration} to get the {@link AuthenticationManager}
     * @return an {@link AuthenticationManager} implementation
     * @throws Exception if there is an error obtaining the authentication manager
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Provides a {@link PasswordEncoder} bean.
     * <p>
     * This encoder is used to encode and decode passwords. {@link BCryptPasswordEncoder} is used for hashing passwords.
     * </p>
     *
     * @return a {@link PasswordEncoder} implementation
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}