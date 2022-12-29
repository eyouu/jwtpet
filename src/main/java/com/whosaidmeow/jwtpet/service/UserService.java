package com.whosaidmeow.jwtpet.service;

import com.whosaidmeow.jwtpet.model.Role;
import com.whosaidmeow.jwtpet.model.User;

import java.util.List;

public interface UserService {

    List<User> getAllUsers();

    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);
}
