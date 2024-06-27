package com.example.securityjwttemplate.member;

import com.example.securityjwttemplate.jwt.JwtUtil;
import com.example.securityjwttemplate.member.domain.MemberEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public MemberEntity signup(String username, String password) {
        MemberEntity newMember = new MemberEntity(username, passwordEncoder.encode(password));
        return memberRepository.save(newMember);
    }

    public Map<String, String> login(String username, String password) {
        MemberEntity member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        String accessToken = jwtUtil.createToken(username, member.getRole().name());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        return tokens;
    }
}
