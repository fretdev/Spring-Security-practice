package com.fretdev.security_practice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private static final String ROLES_CLAIM = "roles";
    private final JwtProperties jwtProperties;
    private final SecretKey jwtSecretKey;
    private final JwtParser jwtParser;

    public String generateToken(UserDetails user){
        Instant now = Instant.now();
        Instant expiry = now.plus(jwtProperties.expiration(), ChronoUnit.MINUTES);
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(jwtProperties.issuer())
                .subject(user.getUsername())
                .claim(ROLES_CLAIM,roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(jwtSecretKey)
                .compact();
    }
    private Optional<Claims> parseClaims(String token){
        try{
            return Optional.of(jwtParser.parseSignedClaims(token).getPayload());
        }catch(ExpiredJwtException e){
            log.debug("Jwt Expired");
        }catch(JwtException | IllegalArgumentException e){
            log.warn("Invalid Jwt Token: {}",e.getMessage());
        }
        return Optional.empty();
    }
    public Optional<String> getUsername(String token){
        return parseClaims(token).map(Claims::getSubject);
    }

    public List<String> getRoles(String token){
        return parseClaims(token).map(claims -> claims.get(ROLES_CLAIM))
                .filter(List.class::isInstance)
                .map(raw ->((List<?>) raw).stream().map(String::valueOf).toList())
                .orElse(List.of());
    }

    public boolean isTokenValid(String token,UserDetails user){
        return parseClaims(token).map(claims -> user.getUsername().equals(claims.getSubject()))
                .orElse(false);
    }
 }

