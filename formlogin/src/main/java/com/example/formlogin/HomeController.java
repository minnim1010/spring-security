package com.example.formlogin;

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
        return String.format("Hello %s", member);
    }

    @GetMapping("/no-auth")
    @ResponseStatus(HttpStatus.OK)
    public String noAuth(){
        return "You are anonymous!";
    }

    @GetMapping("/user")
    @ResponseStatus(HttpStatus.OK)
    public String user(){
        return "You are user!";
    }

    @GetMapping("/admin")
    @ResponseStatus(HttpStatus.OK)
    public String admin(){
        return "You are admin!";
    }
}
