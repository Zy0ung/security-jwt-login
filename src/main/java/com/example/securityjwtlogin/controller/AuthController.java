/*
 * Copyright ⓒ 2017 Brand X Corp. All Rights Reserved
 */
package com.example.securityjwtlogin.controller;


import com.example.securityjwtlogin.dto.LoginDto;
import com.example.securityjwtlogin.dto.TokenDto;
import com.example.securityjwtlogin.jwt.JwtFilter;
import com.example.securityjwtlogin.jwt.TokenProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider,
            AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        // LoginDto를 이용해 username과 password를 받고 UsernamePasswordAuthenticationToken을 생성합니다.
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(), loginDto.getPassword());

        // authenticationToken을 이용해서 authentication 객체를 생성하기 위해 authenticate 메서드가 실행될 때,
        // CustomUserDetailsService 에서 구현한 loadUserByUsername 메서드가 실행되고 최종적으로 Authentication 객체가 생성됩니다.
        Authentication authentication = authenticationManagerBuilder.getObject()
                                                                    .authenticate(authenticationToken);

        //  생성된 Authentication 객체를 SecurityContext에 저장합니다.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //  Authentication 객체를  createToken 메서드를 통해  JWT Token을 생성합니다.
        String jwt = tokenProvider.createToken(authentication);


        HttpHeaders httpHeaders = new HttpHeaders();

        // 생성된 Jwt 토큰을 Response Header에 넣어줍니다.
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        // TokenDto 를 이용해 ResponseBody 에도 넣어 리턴합니다.
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}