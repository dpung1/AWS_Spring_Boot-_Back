package com.toyproject.instagram.exception;

import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthenticateExceptionEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("errorMessage", getErrorMessage(authException));

        JsonMapper jsonMapper = new JsonMapper();

        // Jackson 라이브러리 Map을 JSON문자열로 변환
        String responseJson = jsonMapper.writeValueAsString(errorMap);

        response.getWriter().println(responseJson);
    }

    private String getErrorMessage(AuthenticationException authException) {
        if(authException.getClass() == BadCredentialsException.class) {
            return "잘못된 사용자 정보입니다. 다시 확인하세요.";
        }else if(authException.getClass() == UsernameNotFoundException.class) {
            return "잘못된 사용자 정보입니다. 다시 확인하세요.";
        }else if(authException.getClass() == AccountExpiredException.class) {
            return "만료된 사용자 정보입니다. 다시 확인하세요.";
        }else if(authException.getClass() == CredentialsExpiredException.class) {
            return "인증서가 만료되었습니다. 관리자에게 문의하세요.";
        }else if(authException.getClass() == DisabledException.class) {
            return "비활성화된 사용자 정보입니다. 관리자에게 문의하세요.";
        }else if(authException.getClass() == LockedException.class) {
            return "암호 오류 5회 이상. 관리자에게 문의하세요.";
        }else {
            return "사용자 정보 오류";
        }
    }
}
