package com.javarush.jira.login.internal.jwt;


import com.javarush.jira.login.AuthUser;
import com.javarush.jira.login.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.checkerframework.checker.units.qual.C;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    public final static String JWT_COOKIE_NAME = "JWT";

    @Value("${token.signing.key}")
    private String jwtSigningKey;

    // check
    public boolean isTokenValid(String token, User user) {
        final String userName = extractEmail(token);
        final boolean isTokenExpired = extractClaim(token, Claims::getExpiration).before(new Date());
        return (userName.equals(user.getEmail())) && !isTokenExpired;
    }

    // generate

    public String generateToken(AuthUser authUser) {
        return Jwts.builder()
                .setClaims(Map.of("email", authUser.getUsername()))
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 100000 * 60 * 24))
                .signWith(getSigningKey()).compact();
    }

    // extract

    public String extractEmail(String token) {
        return extractClaim(token, (claims) -> (String) claims.get("email"));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimResolvers.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSigningKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
