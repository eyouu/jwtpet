package com.whosaidmeow.jwtpet.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.whosaidmeow.jwtpet.model.Role;
import com.whosaidmeow.jwtpet.model.User;
import com.whosaidmeow.jwtpet.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.whosaidmeow.jwtpet.security.filter.CustomAuthenticationFilter.*;
import static com.whosaidmeow.jwtpet.security.filter.CustomAuthorizationFilter.BEARER_PREFIX;
import static com.whosaidmeow.jwtpet.security.filter.CustomAuthorizationFilter.sendErrorInBody;
import static java.lang.System.currentTimeMillis;
import static java.util.stream.Collectors.toList;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok().body(userService.getAllUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/save").toUriString());

        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/role/save").toUriString());

        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/add-role-to-user")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());

        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            try {
                String jwtRefreshToken = authorizationHeader.substring(BEARER_PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET_KEY);
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(jwtRefreshToken);

                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);

                String accessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withIssuer(request.getRequestURL().toString())
                        .withExpiresAt(new Date(currentTimeMillis() + TEN_MINUTES))
                        .withClaim(KET_FOR_AUTHORITIES, user.getRoles().stream().map(Role::getName).collect(toList()))
                        .sign(algorithm);

                sendTokensInBody(response, accessToken, jwtRefreshToken);

            } catch (Exception exception) {
                log.error("Error logging in {}", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                sendErrorInBody(response, exception.getMessage());
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}

@Data
class RoleToUserForm {

    private String username;
    private String roleName;
}
