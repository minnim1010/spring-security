package com.example.restjwt;

import com.example.database.member.entity.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class HomeController {

    @GetMapping("/")
    @ResponseStatus(HttpStatus.OK)
    public String home(@AuthenticationPrincipal Member member){
        return String.format("Hello %s",
            member == null ? null : member.getUsername());
    }

    @GetMapping("/user")
    @ResponseStatus(HttpStatus.OK)
    public String user(@AuthenticationPrincipal Member member){
        return String.format("You are user! Hello %s", member.getUsername());
    }

    @GetMapping("/admin")
    @ResponseStatus(HttpStatus.OK)
    public String admin(@AuthenticationPrincipal Member member){
        return String.format("You are admin! Hello %s", member.getUsername());
    }
}
