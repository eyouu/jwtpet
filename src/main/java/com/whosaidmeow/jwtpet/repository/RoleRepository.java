package com.whosaidmeow.jwtpet.repository;

import com.whosaidmeow.jwtpet.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByName(String name);
}
