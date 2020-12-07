package com.shafiquech.sample.jwt.util;

import static java.time.temporal.ChronoUnit.MINUTES;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JWTUtil implements Serializable {


  private static final long JWT_TOKEN_VALIDITY = 2;

  @Value("${jwt.secret.key}")
  private String jwtSecretKey;

  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return doGenerateToken(claims, userDetails.getUsername());
  }

  private String doGenerateToken(Map<String, Object> claims, String username) {
    return Jwts.builder()
        .setClaims(claims)
        .setSubject(username)
        .setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
        .setExpiration(Date.from(
            LocalDateTime.now().plus(JWT_TOKEN_VALIDITY, MINUTES).atZone(ZoneId.systemDefault())
                .toInstant()))
        .signWith(SignatureAlgorithm.HS512, jwtSecretKey)
        .compact();


  }

  public boolean validateToken(String token, UserDetails userDetails) {
    final String username = getUsernameFromToken(token);
    return username.equals(userDetails.getUsername()) && !isTokenExpired(token);

  }

  private boolean isTokenExpired(String token) {
    final Date expiration = getExpirationDateFromToken(token);
    return expiration.before(new Date());
  }

  private Date getExpirationDateFromToken(String token) {
    return getClaimFromToken(token, Claims::getExpiration);
  }

  public String getUsernameFromToken(String token) {
    return getClaimFromToken(token, Claims::getSubject);
  }

  private Claims getAllClaimsFromToken(String token) {
    return Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJws(token).getBody();
  }

  private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = getAllClaimsFromToken(token);
    return claimsResolver.apply(claims);
  }

}
