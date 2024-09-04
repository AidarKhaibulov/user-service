package ru.userservice.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.userservice.dto.auth.AuthenticationRequest;
import ru.userservice.dto.auth.AuthenticationResponse;
import ru.userservice.dto.auth.RegisterRequest;
import ru.userservice.enums.TokenType;
import ru.userservice.models.Token;
import ru.userservice.models.User;
import ru.userservice.repositories.TokenRepository;
import ru.userservice.repositories.UserRepository;

import java.io.IOException;

/**
 * Service class for handling user authentication and token management.
 * <p>
 * This class provides methods for registering new users, authenticating existing users,
 * refreshing tokens, and managing user tokens.
 * </p>
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Registers a new user and generates authentication tokens.
     * <p>
     * This method creates a new user with the provided details, encodes the user's password,
     * and saves the user to the database. It also generates an access token and a refresh token,
     * and saves the access token in the database.
     * </p>
     *
     * @param request the {@link RegisterRequest} containing user registration details
     * @return an {@link AuthenticationResponse} containing the access and refresh tokens
     */
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Authenticates a user and generates new tokens.
     * <p>
     * This method authenticates the user using the provided email and password. If authentication
     * is successful, it generates a new access token and a refresh token, revokes any previous tokens,
     * and saves the new access token in the database.
     * </p>
     *
     * @param request the {@link AuthenticationRequest} containing user credentials
     * @return an {@link AuthenticationResponse} containing the access and refresh tokens
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Saves a user token to the database.
     * <p>
     * This method creates and saves a new {@link Token} entity for the specified user and token.
     * </p>
     *
     * @param user     the {@link User} associated with the token
     * @param jwtToken the token to be saved
     */
    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    /**
     * Revokes all valid tokens for a user.
     * <p>
     * This method finds all valid tokens for the specified user and marks them as expired and revoked.
     * </p>
     *
     * @param user the {@link User} whose tokens are to be revoked
     */
    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    /**
     * Refreshes the access token for a user.
     * <p>
     * This method extracts the refresh token from the request, verifies its validity, and generates a new
     * access token if the refresh token is valid. It also revokes old tokens and sends the new tokens
     * in the response.
     * </p>
     *
     * @param request  the {@link HttpServletRequest} containing the refresh token
     * @param response the {@link HttpServletResponse} to write the new tokens to
     * @throws IOException if there is an error writing the response
     */
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}