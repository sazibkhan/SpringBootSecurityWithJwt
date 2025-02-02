package com.sazibeng.SpringBootSecurityWithJwt.repository;

import com.sazibeng.SpringBootSecurityWithJwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IUserRepository extends JpaRepository<User,Long> {

    Optional<User> findByEmail(String username);

}
