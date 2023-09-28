package com.example.database.member.entity;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.Collection;
import java.util.List;

@ToString
@NoArgsConstructor
@Entity
public class Member implements UserDetails {
    @Getter
    @Id @GeneratedValue
    private Long id;

    private String username;

    private String oauth2Name;

    private String password;

    private String email;

    private boolean enable;

    @Enumerated(EnumType.STRING)
    private Authority authority;

    @Builder
    private Member(Long id, String username, String oauth2Name,
                   String password, String email, Authority authority, boolean enable) {
        this.id = id;
        this.username = username;
        this.oauth2Name = oauth2Name;
        this.password = password;
        this.email = email;
        this.authority = authority;
        this.enable = enable;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String authorityString = authority.name();

        return List.of(new SimpleGrantedAuthority(authorityString));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getOauth2Name() {
        return oauth2Name;
    }

    public Member updateOauth2Name(String oauth2Name) {
        this.oauth2Name = oauth2Name;
        return this;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
