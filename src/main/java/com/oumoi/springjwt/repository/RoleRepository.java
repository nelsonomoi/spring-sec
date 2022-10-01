package com.oumoi.springjwt.repository;


import com.oumoi.springjwt.model.ERole;
import com.oumoi.springjwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(ERole name);
}
