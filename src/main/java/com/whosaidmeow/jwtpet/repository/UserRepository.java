package com.whosaidmeow.jwtpet.repository;

import com.whosaidmeow.jwtpet.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
