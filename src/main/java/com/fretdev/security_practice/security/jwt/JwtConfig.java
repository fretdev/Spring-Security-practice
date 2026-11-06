package com.fretdev.security_practice.security.jwt;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {
    @Bean
    public SecretKey jwtSecretKey(JwtProperties jwtProperties){
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.secret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Bean
    public JwtParser jwtParser(JwtProperties jwtProperties,SecretKey jwtSecretKey){
        return Jwts.parser()
                .verifyWith(jwtSecretKey)
                .requireIssuer(jwtProperties.issuer())
                .clockSkewSeconds(jwtProperties.clockSkewSeconds())
                .build();
    }
}
