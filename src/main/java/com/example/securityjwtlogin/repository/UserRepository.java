package com.example.securityjwtlogin.repository;

import com.example.securityjwtlogin.entity.User;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // username 을 기준으로 User 정보를 가져올 권한정보도 같이 가져옴
    @EntityGraph(attributePaths = "authorities") // 쿼리 수행 시 Lazy 조회가 아닌, Eager 조회로 authorities 정보를 같이가져옴
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}