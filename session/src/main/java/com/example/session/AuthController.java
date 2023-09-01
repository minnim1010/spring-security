package com.example.session;

import com.example.database.member.entity.Authority;
import com.example.database.member.entity.Member;
import com.example.database.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AuthController {

    private final MemberRepository memberRepository;

    @GetMapping("/join")
    @ResponseStatus(HttpStatus.OK)
    public void join() {
        Member member = Member.builder()
            .username("TestUser")
            .password("password")
            .authority(Authority.ROLE_USER)
            .build();

        memberRepository.save(member);
    }
}
