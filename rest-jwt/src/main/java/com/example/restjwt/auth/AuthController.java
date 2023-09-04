package com.example.restjwt.auth;

import com.example.database.member.entity.Member;
import com.example.restjwt.auth.dto.LoginRequest;
import com.example.restjwt.auth.dto.LoginResponse;
import com.example.restjwt.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AuthController {

    private final JwtProvider jwtProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public LoginResponse login(@RequestBody LoginRequest request){
        UsernamePasswordAuthenticationToken unauthenticatedToken
            = UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password());
        Authentication authenticatedToken = authenticationManagerBuilder.getObject().authenticate(unauthenticatedToken);

        Member member = (Member) authenticatedToken.getPrincipal();
        String token = jwtProvider.createToken(member);

        return new LoginResponse(token);
    }
}
