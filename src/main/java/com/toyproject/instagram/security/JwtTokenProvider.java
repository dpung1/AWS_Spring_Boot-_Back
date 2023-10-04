package com.toyproject.instagram.security;

import com.toyproject.instagram.entity.User;
import com.toyproject.instagram.repository.UserMapper;
import com.toyproject.instagram.service.PrincipalDetailsService;
import com.toyproject.instagram.service.UserService;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

// Jwt 토큰을 관리해주는 로직
@Component
public class JwtTokenProvider {

    private final Key key;
    private final PrincipalDetailsService principalDetailsService;
    private final UserMapper userMapper;


    // AUtowired는 Ioc 컨테이너에서 객체를 자동 주입
    // Value는 application.yml에서 변수 데이터를 자동 주입
    public JwtTokenProvider(@Value("${jwt.secret}")String secret,
                            @Autowired PrincipalDetailsService principalDetailsService,
                            @Autowired UserMapper userMapper) {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.principalDetailsService = principalDetailsService;
        this.userMapper = userMapper;
    }

    // JWT 토큰을 생성
    public String generateAccessToken(Authentication authentication) {

        String accessToken = null;

        PrincipalUser principalUser = (PrincipalUser) authentication.getPrincipal();

        Date tokenExpiresDate = new Date(new Date().getTime() + (1000 * 60 * 60 *24));
        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject("AccessToken") // 토큰의 이름
                .setExpiration(tokenExpiresDate) // 만료일
                .signWith(key, SignatureAlgorithm.HS256);// 만들어놓은 키값

        User user = userMapper.findUserByPhone(principalUser.getUsername());
        if(user != null) {
            return jwtBuilder.claim("username", user.getUsername()).compact();
        }

        user = userMapper.findUserByEmail(principalUser.getUsername());
        if(user != null) {
            return jwtBuilder.claim("username", user.getUsername()).compact();
        }

        return jwtBuilder.claim("username",principalUser.getUsername()).compact();
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

    public Authentication getAuthentication(String accessToken) {
        Authentication authentication = null;

        String username = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(accessToken)
                .getBody()
                .get("username")
                .toString();

        PrincipalUser principalUser =  (PrincipalUser) principalDetailsService.loadUserByUsername(username);

        authentication = new UsernamePasswordAuthenticationToken(principalUser, null, principalUser.getAuthorities());

        return authentication;
    }
}
