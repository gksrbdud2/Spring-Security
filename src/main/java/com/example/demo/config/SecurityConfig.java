package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.demo.service.MemberService;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity //Spring Security를 설정할 클래스라고 정의 WebSecurityConfigurerAdapter클래스를 상속받아 메서드를 구현
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private MemberService memberService;

    @Bean //Service에서 비밀번호를 암호화할 수 있도록 Bean으로 등록
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();   //BCryptPasswordEncoder는 Spring Security에서 제공하는 비밀번호 암호화 객체. 
    }

    @Override
    public void configure(WebSecurity web) throws Exception  // WebSecurity는 FilterChainProxy를 생성하는 필터
    {
        // static 디렉터리의 하위 파일 목록은 인증 무시 ( = 항상통과 )
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception { //HttpSecurity를 통해 HTTP요청에 대한 웹 기반 보안을 구성할 수 있다.
        http.authorizeRequests() //HttpServletRequest에 따라 접근을 제한한다.
                // 페이지 권한 설정(역할에 따른 접근 설정)
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/myinfo").hasRole("MEMBER")
                .antMatchers("/**").permitAll()
                // .anyRequest().authenticated() : 모든 요청에 대해, 인증된 사용자만 접근하도록 설정할 수도 있다.
            .and() // 로그인 설정
                .formLogin() //form 태그 기반의 로그인을 지원하겠다는 설정 
                .loginPage("/user/login") // 기본제공되는 form 은 /login이다. 기본 경로로 지정하면 스프링시큐어리티에서 제공하는 기본 로그인 화면을 볼 수 있다.
                .defaultSuccessUrl("/user/login/result")
                .permitAll()
                // 로그인 form에서 아이디는 name=username인 input을 기본으로 인식하는데, usernameParameter("파라미터명")메서드를 통해 파라미터명을 변경할 수 있다.
            .and() // 로그아웃 설정
                .logout()
                //.logoutUrl("/logout") -> 이게 default
                .logoutRequestMatcher(new AntPathRequestMatcher("/user/logout")) //기본적으로 "/logout"에 접근하면 HTTP세션을 제거한다. 이 메서드는 /logout이 아닌 다른 URL로 재정의한다.
                .logoutSuccessUrl("/user/logout/result")
                .invalidateHttpSession(true) //http 세션을 초기화하는 작업(Spring Security가 웹을 처리하는 기본 방식은 HttpSession)
                //deleteCookies("KEY명") 로그아웃 시,특정 쿠키를 제거하고 싶을 때 사용하는 메서드
            .and()
                // 403 예외처리 핸들링
                .exceptionHandling().accessDeniedPage("/user/denied"); //예외가 발생했을 때 exceptionHandling()메서드로 핸들링, 여기서는 접근권한이 없을 때 권한없음 페이지로 이동하도록 명시
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception { //Spring Security에서 모든 인증은 AuthenticationManager를 통해 이루어진다.
        auth.userDetailsService(memberService).passwordEncoder(passwordEncoder()); 
        //로그인 처리, 즉 인증을 위해서는 UserDetailsService를 통해서 필요한 정보들을 가져옵니다. memberService클래스에서 userDetailsServce를 implements하고 로그인 메서드를 구현.
    }
}