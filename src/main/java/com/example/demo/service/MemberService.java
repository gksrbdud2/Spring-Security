package com.example.demo.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.domain.Role;
import com.example.demo.dto.MemberDto;
import com.example.demo.entity.Member_entity;
import com.example.demo.repository.MemberRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class MemberService implements UserDetailsService {
    private MemberRepository memberRepository;

//    //회원가입
//    @Transactional
//    public Long joinUser(MemberDto memberDto) {
//        // 비밀번호 암호화 하여 저장
//               BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//        memberDto.setPassword(passwordEncoder.encode(memberDto.getPassword()));
//
//        return memberRepository.save(memberDto.toEntity()).getId();
//    }
    
    //회원가입
    @Transactional
    public Long joinUser(MemberDto memberDto) {
        // 비밀번호 암호화 하여 저장
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        
        memberDto.setPassword(passwordEncoder.encode(memberDto.getPassword()));

        return memberRepository.save(memberDto.toEntity()).getId();
    }

    //로그인 : 매개변수(userEmail)는 로그인 시 입력한 아이디인데, pk를 뜻하는게 아닌 유저를 식별할 수 있는 어떤 값을 의미하며 spring security에서는 username이라는 이름으로 사용
    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        Optional<Member_entity> userEntityWrapper = memberRepository.findByEmail(userEmail);
        Member_entity userEntity = userEntityWrapper.get();

        List<GrantedAuthority> authorities = new ArrayList<>();

        if (("admin@example.com").equals(userEmail)) {
            authorities.add(new SimpleGrantedAuthority(Role.ADMIN.getValue()));  //롤을 부여하는 코드. Role Entity를 만들어서 매핑해줌.
        } else {
            authorities.add(new SimpleGrantedAuthority(Role.MEMBER.getValue()));
        }

        //생성자의 각 매개변수는 순서대로 아이디, 비밀번호, 권한리스트
        return new User(userEntity.getEmail(), userEntity.getPassword(), authorities); //사용자의 계정정보와 권한을 갖는 UserDetails인터페이스를 반환
    }
}