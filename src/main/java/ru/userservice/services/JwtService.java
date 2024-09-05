package ru.userservice.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import ru.userservice.models.User;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service class for managing JSON Web Tokens (JWTs).
 * <p>
 * This class provides methods for generating, validating, and extracting information from JWTs.
 * It handles both access tokens and refresh tokens, using a secret key and configurable expiration times.
 * </p>
 */
@Service
public class JwtService {

    @Value("${spring.security.jwt.secret-key}")
    private String secretKey;

    @Value("${spring.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${spring.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    /**
     * Extracts the username from the given token.
     * <p>
     * This method retrieves the subject (username) from the JWT claims.
     * </p>
     *
     * @param token the JWT token
     * @return the username extracted from the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts a specific claim from the given token.
     * <p>
     * This method extracts the claims from the token and applies the provided function to retrieve a specific claim.
     * </p>
     *
     * @param token the JWT token
     * @param claimsResolver a function to extract a specific claim from the claims
     * @param <T> the type of the claim
     * @return the extracted claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generates a JWT token based on user details.
     * <p>
     * This method creates a JWT token with default claims and expiration time.
     * </p>
     *
     * @param userDetails the user details for which the token is to be generated
     * @return the generated JWT token
     */
    public String generateToken(User userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with additional claims.
     * <p>
     * This method creates a JWT token with specified claims, user details, and expiration time.
     * </p>
     *
     * @param extraClaims additional claims to be included in the token
     * @param userDetails the user details for which the token is to be generated
     * @return the generated JWT token
     */
    public String generateToken(
            Map<String, Object> extraClaims,
            User userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Generates a refresh token for the user.
     * <p>
     * This method creates a refresh token with the specified expiration time.
     * </p>
     *
     * @param userDetails the user details for which the refresh token is to be generated
     * @return the generated refresh token
     */
    public String generateRefreshToken(
            User userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    /**
     * Builds a JWT token with the given claims, user details, and expiration time.
     * <p>
     * This method creates and signs the token using the secret key and specified expiration time.
     * </p>
     *
     * @param extraClaims additional claims to be included in the token
     * @param userDetails the user details for which the token is to be generated
     * @param expiration the expiration time of the token in milliseconds
     * @return the generated JWT token
     */
    private String buildToken(
            Map<String, Object> extraClaims,
            User userDetails,
            long expiration
    ) {
        extraClaims.put("userId", userDetails.getId());
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validates the given token against the user details.
     * <p>
     * This method checks if the token is valid by verifying the username and expiration date.
     * </p>
     *
     * @param token the JWT token to be validated
     * @param userDetails the user details to be checked against
     * @return true if the token is valid, otherwise false
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Checks if the given token has expired.
     * <p>
     * This method compares the expiration date of the token with the current date.
     * </p>
     *
     * @param token the JWT token to be checked
     * @return true if the token is expired, otherwise false
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date from the given token.
     * <p>
     * This method retrieves the expiration date claim from the token.
     * </p>
     *
     * @param token the JWT token
     * @return the expiration date of the token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extracts all claims from the given token.
     * <p>
     * This method parses the token and retrieves the claims using the signing key.
     * </p>
     *
     * @param token the JWT token
     * @return the claims extracted from the token
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Retrieves the signing key for JWTs.
     * <p>
     * This method decodes the base64-encoded secret key and returns the key used for signing tokens.
     * </p>
     *
     * @return the signing key for JWTs
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}