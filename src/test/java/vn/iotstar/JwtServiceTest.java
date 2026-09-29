package vn.iotstar;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;
import vn.iotstar.exceptions.ExpiredJwtTokenException;
import vn.iotstar.exceptions.InvalidJwtException;
import vn.iotstar.services.JwtService;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private JwtService jwtService;
    private final String secretHex = "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", secretHex);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3600000L);
    }

    @Test
    void testGenerateAndValidateToken() {
        UserDetails userDetails = new User("admin@test.com", "password", Collections.emptyList());

        String token = jwtService.generateToken(userDetails);
        assertNotNull(token);

        String username = jwtService.extractUsername(token);
        assertEquals("admin@test.com", username);

        boolean isValid = jwtService.isTokenValid(token, userDetails);
        assertTrue(isValid);
    }

    @Test
    void testGenerateWithExtraClaims() {
        UserDetails userDetails = new User("user@test.com", "password", Collections.emptyList());

        String token = jwtService.generateToken(Map.of("role", "ADMIN"), userDetails);
        assertNotNull(token);

        String role = jwtService.extractClaim(token, claims -> claims.getClaim("role").toString());
        assertEquals("ADMIN", role);
    }

    @Test
    void testInvalidTokenThrowsException() {
        assertThrows(InvalidJwtException.class, () -> jwtService.extractUsername("invalid.token.structure"));
    }

    @Test
    void testExpiredTokenThrowsException() {
        JwtService shortLivedJwtService = new JwtService();
        ReflectionTestUtils.setField(shortLivedJwtService, "secretKey", secretHex);
        ReflectionTestUtils.setField(shortLivedJwtService, "jwtExpiration", -1000L);

        UserDetails userDetails = new User("expired@test.com", "password", Collections.emptyList());
        String token = shortLivedJwtService.generateToken(userDetails);

        assertThrows(ExpiredJwtTokenException.class, () -> jwtService.extractUsername(token));
    }
}
