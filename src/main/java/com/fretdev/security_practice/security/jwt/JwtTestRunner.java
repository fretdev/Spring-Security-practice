package com.fretdev.security_practice.security.jwt;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTestRunner implements CommandLineRunner {
    private final JwtService jwtService;

    @Override
    public void run(String @NonNull ... args) throws Exception{
        UserDetails user = User.withUsername("Fretdev")
                .password("testing and learning")
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("Fretdev")
                        .password("admin1234")
                        .roles("ADMIN")
                        .build();
        System.out.println("User-Token: " + jwtService.generateToken(user));
        System.out.println("Admin-Token: " + jwtService.generateToken(admin));

    }
}
