package com.toyproject.instagram.dto;

import lombok.Data;

@Data
public class SigninReqDto {

    private String phoneOrEmailOrUsername;
    private String loginPassword;
}
