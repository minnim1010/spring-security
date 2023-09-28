package com.example.oauth2.jwt;

import java.util.Date;

public record Jwt(Long id, String username, String authority, Date issuedAt, Date expiresAt) {
}
