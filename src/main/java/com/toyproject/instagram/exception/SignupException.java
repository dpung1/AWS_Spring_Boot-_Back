package com.toyproject.instagram.exception;

import lombok.Getter;

import java.util.Map;

@Getter
public class SignupException extends RuntimeException {

    private Map<String, String> errorMap;

    public SignupException(Map<String, String> errorMap) {
        super("회원가입 유효성 검사 오류");
        this.errorMap = errorMap;
        errorMap.forEach((k, v) -> {
            System.out.println(k + ": " + v);
        });
    }
}
