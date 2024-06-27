package com.example.securityjwttemplate.member;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public void signup(String username, String password) {
        memberRepository.save(new MemberEntity(username, passwordEncoder.encode(password)));
    }
}
