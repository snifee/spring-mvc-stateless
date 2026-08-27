package org.snifee.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Component
@AllArgsConstructor
@NoArgsConstructor
public class JwtComponent {

    @Value(value = "${spring.security.jwt.secret-key}")
    private String secretKey;

    @Value(value = "${spring.security.jwt.expiration}")
    private long expiration;

    @Value(value = "${spring.security.jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    @Value(value = "${spring.security.jwt.refresh-token.secret-key}")
    private String refreshTokenSecretKey;

    public String generateAccessToken(String username, Map<String, Object> claims){
        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .expiration(Date.from(LocalDateTime.now().plusMinutes(expiration).toInstant(ZoneOffset.UTC)))
                .issuedAt(Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)))
                .signWith(getSignInKey())
                .compact();

    }

    public String generateRefreshToken(String username){
        return Jwts.builder()
                .subject(username)
                .signWith(getRefreshTokenKey())
                .expiration(new Date(System.currentTimeMillis() + (refreshTokenExpiration*60*100)))
                .compact();
    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRefreshTokenUsername(String token) {
        return extractRefreshTokenClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private <T> T extractRefreshTokenClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllRefreshTokenClaims(token);
        return claimsResolver.apply(claims);
    }

    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Key getRefreshTokenKey(){
        byte[] keyBytes = Decoders.BASE64.decode(refreshTokenSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getPayload();
    }

    private Claims extractAllRefreshTokenClaims(String token){
        return Jwts.parser()
                .setSigningKey(getRefreshTokenKey())
                .build()
                .parseClaimsJws(token)
                .getPayload();
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Date extractRefreshTokenExpiration(String token) {
        return extractRefreshTokenClaim(token, Claims::getExpiration);
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean isRefreshTokenExpired(String token) {
        return extractRefreshTokenExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public Boolean validateRefreshToken(String token, UserDetails userDetails) {
        final String username = extractRefreshTokenUsername(token);
        return (username.equals(userDetails.getUsername()) && !isRefreshTokenExpired(token));
    }

}
