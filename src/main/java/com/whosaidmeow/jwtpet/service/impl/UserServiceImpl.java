package com.whosaidmeow.jwtpet.service.impl;

import com.whosaidmeow.jwtpet.model.Role;
import com.whosaidmeow.jwtpet.model.User;
import com.whosaidmeow.jwtpet.repository.RoleRepository;
import com.whosaidmeow.jwtpet.repository.UserRepository;
import com.whosaidmeow.jwtpet.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.util.Objects.isNull;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (isNull(user)) {
            log.error("User not found in the database!");
            throw new UsernameNotFoundException("User not found in the database!");
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                prepareAuthorities(user.getRoles())
        );
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        log.info("Getting all the users from the database");
        return userRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public User getUser(String username) {
        log.info("Getting the user: {}", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving the user with username: {}", user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving the role with name: {}", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role: {} to user: {}", roleName, username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    private List<SimpleGrantedAuthority> prepareAuthorities(Set<Role> roles) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        roles.forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));
        return authorities;
    }
}
