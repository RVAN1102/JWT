package vn.iotstar.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import vn.iotstar.exceptions.ExpiredJwtTokenException;
import vn.iotstar.exceptions.InvalidJwtException;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        try {
            Date now = new Date();
            Date validity = new Date(now.getTime() + expiration);

            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(validity);

            extraClaims.forEach(builder::claim);

            JWTClaimsSet claimsSet = builder.build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    claimsSet
            );

            signedJWT.sign(new MACSigner(getSigningKeyBytes()));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new InvalidJwtException("Failed to generate JWT token", e);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {
        Date expiration = extractClaim(token, JWTClaimsSet::getExpirationTime);
        return expiration == null || expiration.before(new Date());
    }

    public SignedJWT parseAndVerifyToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            if (!signedJWT.verify(new MACVerifier(getSigningKeyBytes()))) {
                throw new InvalidJwtException("Invalid JWT signature");
            }
            Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expiration == null || expiration.before(new Date())) {
                throw new ExpiredJwtTokenException("JWT token has expired");
            }
            return signedJWT;
        } catch (ParseException e) {
            throw new InvalidJwtException("Malformed JWT token", e);
        } catch (JOSEException e) {
            throw new InvalidJwtException("JWT verification failed", e);
        }
    }

    private JWTClaimsSet extractAllClaims(String token) {
        try {
            return parseAndVerifyToken(token).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new InvalidJwtException("Failed to parse JWT claims", e);
        }
    }

    private byte[] getSigningKeyBytes() {
        String trimmed = secretKey.trim();
        if (trimmed.length() == 64 && trimmed.matches("^[0-9a-fA-F]+$")) {
            return HexFormat.of().parseHex(trimmed);
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            if (decoded.length >= 32) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
        }
        byte[] raw = trimmed.getBytes(StandardCharsets.UTF_8);
        if (raw.length < 32) {
            throw new IllegalArgumentException("Secret key must be at least 256 bits (32 bytes)");
        }
        return raw;
    }
}
