package com.toyproject.instagram.dto;

import com.toyproject.instagram.entity.User;
import lombok.Data;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

@Data
public class SignupReqDto {
    @Pattern(regexp = "^[a-zA-Z0-9]+@[0-9a-zA-Z]+\\.[a-z]*$|^[\\d]{11}$", message = "이메일 또는 전화번호를 입력하세요.")
    private String phoneAndEmail;
    @Pattern(regexp = "^[가-힣]{2,6}$", message = "이름은 한글만 입력할 수 있습니다.")
    private String name;
    @Pattern(regexp = "^(?=.*[a-z])[a-z0-9_.]*$", message = "이름을 입력하세요.")
    private String username;
    @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*[0-9]).{8,25}$", message = "비밀번호튼 영문, 숫자, 조합으로 8자 이상 입력하세요.")
    private String password;

    public User toUserEntity(BCryptPasswordEncoder passwordEncoder) {
        return User.builder()
                .email(phoneAndEmail)
                .name(name)
                .username(username)
                .password(passwordEncoder.encode(password))
                .build();
    }
}
