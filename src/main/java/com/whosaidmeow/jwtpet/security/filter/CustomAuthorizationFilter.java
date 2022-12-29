package com.whosaidmeow.jwtpet.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.whosaidmeow.jwtpet.security.filter.CustomAuthenticationFilter.JWT_SECRET_KEY;
import static com.whosaidmeow.jwtpet.security.filter.CustomAuthenticationFilter.KET_FOR_AUTHORITIES;
import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * Intercepts every request (here we do JWT token validation)
 */

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    public static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) { // If this is login request, we do nothing
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
                try {
                    String jwtToken = authorizationHeader.substring(BEARER_PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET_KEY);
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(jwtToken);

                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim(KET_FOR_AUTHORITIES).asArray(String.class);

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, mapAuthorities(roles));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    log.error("Error logging in {}", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    sendErrorInBody(response, exception.getMessage());
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }

    private Set<SimpleGrantedAuthority> mapAuthorities(String[] roles) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

        return authorities;
    }

    public static void sendErrorInBody(HttpServletResponse response, String message) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("Error-message", message);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}
