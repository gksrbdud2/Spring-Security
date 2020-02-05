package com.example.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.Member_entity;

public interface MemberRepository extends JpaRepository<Member_entity, Long> {
    Optional<Member_entity> findByEmail(String userEmail);
}