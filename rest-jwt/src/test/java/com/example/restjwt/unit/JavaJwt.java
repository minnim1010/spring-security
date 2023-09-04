package com.example.restjwt.unit;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JavaJwt {

    @DisplayName("java-jwt jwt resolve test")
    @Test
    void test(){
        //given
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdHkiOiJST0xFX1VTRVIiLCJpc3MiOiJSRVNUSldUIiwiaWQiOjEsImV4cCI6MTY5MzgzODMzMiwiaWF0IjoxNjkzODM2NTMyLCJ1c2VybmFtZSI6InVzZXIifQ.56KPbway2dCSkhtYlpm7RIsNH2a_RWbfuQ9wN07xw-A";
        DecodedJWT decodedJwt = JWT.decode(token);

        //when
        String username = decodedJwt.getClaim("username").asString();

        //then
        assertThat(username).isEqualTo("user");
        System.out.println(username);
    }

}
