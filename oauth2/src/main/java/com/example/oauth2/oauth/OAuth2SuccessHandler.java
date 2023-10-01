package com.example.oauth2.oauth;

import com.example.database.member.entity.Member;
import com.example.database.member.repository.MemberRepository;
import com.example.oauth2.jwt.JwtProvider;
import com.example.oauth2.oauth.dto.AccessTokenDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    public static final String REDIRECT_PATH = "/";
    private static final String OAUTH2_USER_ATTRIBUTE_KEY = "email";

    private final JwtProvider jwtProvider;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;
    private final MemberRepository memberRepository;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Member member = memberRepository
            .findByEmail((String) oAuth2User.getAttributes().get(OAUTH2_USER_ATTRIBUTE_KEY))
            .orElseThrow(() -> new IllegalStateException("회원을 찾을 수 없습니다."));

        String accessToken = jwtProvider.createToken(member);

        setResponse(response, new AccessTokenDto(accessToken));
        clearAuthenticationAttributes(request, response);
    }

    private void setResponse(HttpServletResponse response, AccessTokenDto accessToken) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK); //200
        response.setHeader("content-type", "application/json");
        response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));

        String result = objectMapper.writeValueAsString(accessToken);
        response.getWriter().write(result);
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
}