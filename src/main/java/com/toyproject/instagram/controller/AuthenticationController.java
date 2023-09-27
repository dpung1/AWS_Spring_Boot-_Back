package com.toyproject.instagram.controller;

import com.toyproject.instagram.dto.SigninReqDto;
import com.toyproject.instagram.dto.SignupReqDto;
import com.toyproject.instagram.exception.SignupException;
import com.toyproject.instagram.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserService userService;

    @PostMapping("/user")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupReqDto signupReqDto, BindingResult bindingResult) {

        if(bindingResult.hasErrors()) {

            Map<String, String> errorMap = new HashMap<>();

            bindingResult.getFieldErrors().forEach(error -> {
                errorMap.put(error.getField(), error.getDefaultMessage());
            });

            throw new SignupException(errorMap);
        }

        userService.signupUser(signupReqDto);
        return ResponseEntity.ok(null);
    }

    @PostMapping("/login")
    public ResponseEntity<?> signin(@RequestBody SigninReqDto signinReqDto) {

        String accessToken = userService.signinUser(signinReqDto);

        return ResponseEntity.ok().body(accessToken);
    }

    @GetMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestHeader(value = "Authorization") String token) {
        return ResponseEntity.ok(userService.authenticate(token));
    }
}
