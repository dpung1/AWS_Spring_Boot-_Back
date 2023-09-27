package com.toyproject.instagram.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

// Jwt 토큰을 관리해주는 로직
@Component
public class JwtTokenProvider {

    private final Key key;


    // AUtowired는 Ioc 컨테이너에서 객체를 자동 주입
    // Value는 application.yml에서 변수 데이터를 자동 주입
    public JwtTokenProvider(@Value("${jwt.secret}")String secret) {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    // JWT 토큰을 생성
    public String generateAccessToken(Authentication authentication) {

        String accessToken = null;

        PrincipalUser principalUser = (PrincipalUser) authentication.getPrincipal();

        System.out.println(authentication.getPrincipal().getClass());

        Date tokenExpiresDate = new Date(new Date().getTime() + (1000 * 60 * 60 *24));

        accessToken = Jwts.builder()
                .setSubject("AccessToken") // 토큰의 이름
                .claim("username", principalUser.getUsername())
                .setExpiration(tokenExpiresDate) // 만료일
                .signWith(key, SignatureAlgorithm.HS256)// 만들어놓은 키값
                .compact();

        return accessToken;
    }

    public Boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
        }catch (Exception e) {
            return false;
        }
        return true;
    }

    public String convertToken(String bearerToken) {
        String type = "Bearer ";
        // 널인지 확인, 공백인지 확인 = hasText
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith(type)) {
            return bearerToken.substring(type.length());
                                // subString = 문자열 짜르기
        }
        return "";
    }
}
