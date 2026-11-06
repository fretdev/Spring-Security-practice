package com.fretdev.security_practice.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional<String> token = extractToken(request);
        if(token.isPresent() && SecurityContextHolder.getContext().getAuthentication() ==null){
            authenticate(token.get(),request);
        }
        filterChain.doFilter(request,response);
    }

    private void authenticate(String token,HttpServletRequest request){
        Optional<String> username = jwtService.getUsername(token);
        if(username.isEmpty()){
            return;
        }
        List<SimpleGrantedAuthority> authorities = jwtService.getRoles(token).stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username.get(),null,authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    private Optional<String> extractToken(HttpServletRequest request){
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        String bearer_Prefix = "Bearer ";
        if(header == null || !header.startsWith(bearer_Prefix)){
            return Optional.empty();
        }
        String token = header.substring(bearer_Prefix.length()).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }
}
