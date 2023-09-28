package com.example.oauth2.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/social-login")
    public String socialLogin() {
        return "social_login";
    }
}
