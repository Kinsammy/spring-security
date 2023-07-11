package io.samtech.security.config.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.samtech.security.config.security.util.JwtSecretKey;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
//    private static final String SECRET_KEY ="O44FVQ6MlXUD5oxaPn7D77DfeSAISRw5G0om05SDvMqst6HZvLZ2obVA2XlCFC41";


    @Value("${application.security.jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${application.security.jwt.expiration}")
    private Long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private Long refreshTokenExpiration;


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public  <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails){
       return buildToken(extractClaims, userDetails, jwtExpiration);

    }

    public String generateRefreshToken(
            UserDetails userDetails){
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpiration);

    }

    private String buildToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails,
            long expiration
    ){
        return Jwts
                .builder()
                .setIssuer("SamTech")
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigninKey() {
        byte[] keyByte = Decoders.BASE64.decode(jwtSecretKey);
        return Keys.hmacShaKeyFor(keyByte);
    }
}
