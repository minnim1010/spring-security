package com.example.database.member.entity;

public enum Authority {
    ROLE_USER("사용자"),
    ROLE_ADMIN("관리자");

    private final String displayName;

    Authority(String displayName) {
        this.displayName = displayName;
    }
}
