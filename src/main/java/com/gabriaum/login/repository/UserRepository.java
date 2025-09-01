package com.gabriaum.login.repository;

import com.gabriaum.login.model.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserModel, String> {
    @Override
    Optional<UserModel> findById(String s);
    Optional<UserModel> findByEmail(String email);
}
