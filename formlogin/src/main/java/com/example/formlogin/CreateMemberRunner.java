package com.example.formlogin;

import com.example.database.member.entity.Authority;
import com.example.database.member.entity.Member;
import com.example.database.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class CreateMemberRunner implements CommandLineRunner {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        Member user = Member.builder()
            .username("user")
            .password(passwordEncoder.encode("user"))
            .authority(Authority.ROLE_USER)
            .build();

        Member admin = Member.builder()
            .username("admin")
            .password(passwordEncoder.encode("admin"))
            .authority(Authority.ROLE_ADMIN)
            .build();

        Member savedMember = memberRepository.save(user);
        log.info("Saved user member:{}", savedMember.getUsername());

        savedMember = memberRepository.save(admin);
        log.info("Saved admin member:{}", savedMember.getUsername());
    }
}
