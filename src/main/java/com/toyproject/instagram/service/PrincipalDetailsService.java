package com.toyproject.instagram.service;

import com.toyproject.instagram.entity.User;
import com.toyproject.instagram.repository.UserMapper;
import com.toyproject.instagram.security.PrincipalUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String phoneOrEmailOrUsername) throws UsernameNotFoundException {

        System.out.println("아이디 넘어옴? " + phoneOrEmailOrUsername);

        User user = userMapper.findUserByPhone(phoneOrEmailOrUsername);
        if(user != null) {
            return new PrincipalUser(user.getPhone(), user.getPassword());
        }

        user = userMapper.findUserByEmail(phoneOrEmailOrUsername);
        if(user != null) {
            return new PrincipalUser(user.getEmail(), user.getPassword());
        }

        user = userMapper.findUserByUsername(phoneOrEmailOrUsername);
        if(user != null) {
            return new PrincipalUser(user.getUsername(), user.getPassword());
        }
        throw new UsernameNotFoundException("잘못된 사용자 정보입니다. 다시 확인하세요.");
    }
}

