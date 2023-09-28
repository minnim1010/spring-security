package com.example.oauth2.oauth;

import com.example.database.member.entity.Authority;
import com.example.database.member.entity.Member;
import com.example.database.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;


@RequiredArgsConstructor
@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        updateOrSave(oAuth2User);

        return oAuth2User;
    }

    private void updateOrSave(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String name = (String) attributes.get("name");
        String email = (String) attributes.get("email");

        Member member = memberRepository.findByEmail(email)
            .map(m -> m.updateOauth2Name(name))
            .orElse(
                Member.builder()
                    .username(name)
                    .oauth2Name(name)
                    .email(email)
                    .enable(true)
                    .authority(Authority.ROLE_USER)
                    .build()
            );
        memberRepository.save(member);
    }
}
