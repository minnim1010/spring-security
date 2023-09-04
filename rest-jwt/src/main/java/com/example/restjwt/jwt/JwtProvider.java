package com.example.restjwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.database.member.entity.Authority;
import com.example.database.member.entity.Member;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class JwtProvider {
    private static final String SECRET = "secret";
    private static final String ISSUER = "RESTJWT";
    private static final long ACCESS_TOKEN_DURATION = 1800000;
    private static final String CLAIM_ID = "id";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_AUTHORITY = "authority";

    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;

    public JwtProvider() {
        byte[] keyBytes = SECRET.getBytes();
        this.algorithm = Algorithm.HMAC256(keyBytes);
        this.jwtVerifier = JWT.require(algorithm)
            .withIssuer(ISSUER)
            .build();
    }

    public String createToken(Member member) {
        if(member.getAuthorities().size() > 1){
            throw new IllegalStateException("Member authority field is not plural");
        }

        String authority = ((List<?>) member.getAuthorities()).get(0).toString();

        JWTCreator.Builder builder = JWT.create();
        builder.withIssuer(ISSUER)
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_DURATION))
            .withClaim(CLAIM_ID, member.getId())
            .withClaim(CLAIM_USERNAME, member.getUsername())
            .withClaim(CLAIM_AUTHORITY, authority);

        return builder.sign(algorithm);
    }

    public DecodedJWT verify(String token) throws JWTVerificationException{
            return jwtVerifier.verify(token);
    }

    public static class JwtResolver {

        private JwtResolver(){}

        public static Authentication getAuthentication(DecodedJWT decodedJWT) {
            Jwt jwt = resolveJwt(decodedJWT);

            Member member = Member.builder()
                .id(jwt.id())
                .username(jwt.username())
                .authority(Authority.valueOf(jwt.authority()))
                .build();

            return new UsernamePasswordAuthenticationToken(
                member, "", List.of(new SimpleGrantedAuthority(jwt.authority())));
        }

        private static Jwt resolveJwt(DecodedJWT decodedJWT){
            Claim idClaim = decodedJWT.getClaim(CLAIM_ID);
            Assert.notNull(idClaim, "id field cannot be null");

            Claim usernameClaim = decodedJWT.getClaim(CLAIM_USERNAME);
            Assert.notNull(usernameClaim, "username field cannot be null");

            Claim authorityClaim = decodedJWT.getClaim(CLAIM_AUTHORITY);
            Assert.notNull(authorityClaim, "authority field cannot be null");

            Date issuedAtClaim = decodedJWT.getIssuedAt();
            Assert.notNull(issuedAtClaim, "issuedAt field cannot be null");

            Date expiresAtClaim = decodedJWT.getExpiresAt();
            Assert.notNull(expiresAtClaim, "expiresAt field cannot be null");

            return new Jwt(idClaim.asLong(), usernameClaim.asString(), authorityClaim.asString(), issuedAtClaim, expiresAtClaim);
        }
    }
}
