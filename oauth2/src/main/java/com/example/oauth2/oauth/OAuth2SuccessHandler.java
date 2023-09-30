package com.example.oauth2.oauth;

import com.example.database.member.entity.Member;
import com.example.database.member.repository.MemberRepository;
import com.example.oauth2.jwt.JwtProvider;
import com.example.oauth2.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String REDIRECT_PATH = "/";
    private static final String OAUTH2_USER_ATTRIBUTE_KEY = "email";
    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    private static final String AUTHORIZATION_HEADER_VALUE_PREFIX = "Bearer ";

    private final JwtProvider jwtProvider;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;
    private final MemberRepository memberRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Member member = memberRepository
            .findByEmail((String) oAuth2User.getAttributes().get(OAUTH2_USER_ATTRIBUTE_KEY))
            .orElseThrow(() -> new IllegalStateException("회원을 찾을 수 없습니다."));

        String accessToken = jwtProvider.createToken(member);
        CookieUtil.addCookie(response, AUTHORIZATION_HEADER_NAME,
            AUTHORIZATION_HEADER_VALUE_PREFIX + accessToken, 1800000);

        clearAuthenticationAttributes(request, response);

        getRedirectStrategy().sendRedirect(request, response, REDIRECT_PATH);
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
}
