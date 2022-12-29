package com.whosaidmeow.jwtpet;

import com.whosaidmeow.jwtpet.model.Role;
import com.whosaidmeow.jwtpet.model.User;
import com.whosaidmeow.jwtpet.service.UserService;
import com.whosaidmeow.jwtpet.service.impl.UserServiceImpl;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;

@SpringBootApplication
public class JwtpetApplication {

    private static final String ROLE_USER = "ROLE_USER";
    private static final String ROLE_MANAGER = "ROLE_MANAGER";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ROLE_SUPER_ADMIN = "ROLE_SUPER_ADMIN";

    public static void main(String[] args) {
        SpringApplication.run(JwtpetApplication.class, args);
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, ROLE_USER));
            userService.saveRole(new Role(null, ROLE_MANAGER));
            userService.saveRole(new Role(null, ROLE_ADMIN));
            userService.saveRole(new Role(null, ROLE_SUPER_ADMIN));

            userService.saveUser(new User(null, "Allison Bekker", "alison", "alisonPass", new HashSet<>()));
            userService.saveUser(new User(null, "Robert Barateon", "robert", "robertPass", new HashSet<>()));
            userService.saveUser(new User(null, "John Travolta", "john", "johnPass", new HashSet<>()));
            userService.saveUser(new User(null, "Darwin Rob", "darwin", "darwinPass", new HashSet<>()));

            userService.addRoleToUser("alison", ROLE_USER);
            userService.addRoleToUser("alison", ROLE_MANAGER);
            userService.addRoleToUser("alison", ROLE_ADMIN);
            userService.addRoleToUser("robert", ROLE_USER);
            userService.addRoleToUser("john", ROLE_USER);
            userService.addRoleToUser("alison", ROLE_USER);
            userService.addRoleToUser("alison", ROLE_MANAGER);
            userService.addRoleToUser("alison", ROLE_ADMIN);
            userService.addRoleToUser("alison", ROLE_SUPER_ADMIN);
        };
    }

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
