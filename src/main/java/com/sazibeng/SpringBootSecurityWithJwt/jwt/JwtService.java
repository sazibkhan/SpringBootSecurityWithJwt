package com.sazibeng.SpringBootSecurityWithJwt.jwt;

import com.sazibeng.SpringBootSecurityWithJwt.model.Token;
import com.sazibeng.SpringBootSecurityWithJwt.model.User;
import com.sazibeng.SpringBootSecurityWithJwt.repository.ITokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final ITokenRepository tokenRepository;

    private final String SECREAT_KEY = "65a2fb68ab1477bae629e3a2ff7a2963d011265b68069373e97e106f20358e42";

    public  String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }

    private  boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private  Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    public  <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims claims=extractAllClaims(token);
        return resolver.apply(claims);
    }


    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKry())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigninKry() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECREAT_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }

    public String generateToken(User user) {

        String token = Jwts
                .builder()
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
                .signWith(getSigninKry())
                .compact();
        return token;
    }

    public boolean isValid(String token, UserDetails user) {
        String username = extractUsername(token);

        boolean validToken = tokenRepository.findByToken(token)
                .map(t -> !t.getIsLogout())
                .orElse(false);
        return (username.equals(user.getUsername())) && !isTokenExpired(token) && validToken;

    }




}