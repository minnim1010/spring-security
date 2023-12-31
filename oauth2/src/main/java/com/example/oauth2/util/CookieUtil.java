package com.example.oauth2.util;

import org.springframework.util.SerializationUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CookieUtil {

    private CookieUtil() {
    }

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8)
            .replace("+", "%20");
        Cookie cookie = new Cookie(name, encodedValue);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null){
            return;
        }

        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);

                response.addCookie(cookie);
                break;
            }
        }
    }

    public static String serialize(Object obj){
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(obj));
    }

    public static <T> T deserialize(Cookie cookie, Class<T> cls){
        return cls.cast(SerializationUtils.deserialize(
            Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}

