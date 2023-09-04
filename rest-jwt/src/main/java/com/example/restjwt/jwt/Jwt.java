package com.example.restjwt.jwt;

import java.util.Date;

public record Jwt(Long id, String username, String authority, Date issuedAt, Date expiresAt) {
}
