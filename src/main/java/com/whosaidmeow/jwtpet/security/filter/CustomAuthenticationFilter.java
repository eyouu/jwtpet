package com.whosaidmeow.jwtpet.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.System.currentTimeMillis;
import static java.util.stream.Collectors.toList;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * Performs required for JWT logic during Authentication
 */
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final String JWT_SECRET_KEY = "secretKey";
    public static final String KET_FOR_AUTHORITIES = "roles";
    public static final long TEN_MINUTES = 10 * 60 * 1000;

    private static final long THIRTY_MINUTES = 30 * 60 * 1000;

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) throws IOException {
        User user = (User) authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET_KEY);

        String accessToken = formAccessToken(user, request, algorithm);
        String refreshToken = formRefreshToken(user, request, algorithm);

        // sendTokensInHeaders(response, accessToken, refreshToken); // -> Tokens can also be sent in headers
        sendTokensInBody(response, accessToken, refreshToken);
    }

    public static String formAccessToken(User user, HttpServletRequest request, Algorithm algorithm) {
        List<String> authorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList());

        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuer(request.getRequestURL().toString())
                .withExpiresAt(new Date(currentTimeMillis() + TEN_MINUTES))
                .withClaim(KET_FOR_AUTHORITIES, authorities)
                .sign(algorithm);
    }

    public static String formRefreshToken(User user, HttpServletRequest request, Algorithm algorithm) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuer(request.getRequestURL().toString())
                .withExpiresAt(new Date(currentTimeMillis() + THIRTY_MINUTES))
                .sign(algorithm);
    }

    public static void sendTokensInBody(HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("Access-token", accessToken);
        tokens.put("Refresh-token", refreshToken);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    private void sendTokensInHeaders(HttpServletResponse response, String accessToken, String refreshToken) {
        response.setHeader("Access-token", accessToken);
        response.setHeader("Refresh-token", refreshToken);
    }
}
