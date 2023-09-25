package com.toyproject.instagram.service;

import com.toyproject.instagram.dto.SignupReqDto;
import com.toyproject.instagram.repository.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final BCryptPasswordEncoder passwordEncoder;

    public void signupUser(SignupReqDto signupReqDto) {
        // Service에서 DTO > Entity 변환
        Integer executeCount = userMapper.saveUser(signupReqDto.toUserEntity(passwordEncoder));
        System.out.println(executeCount);
    }
}
