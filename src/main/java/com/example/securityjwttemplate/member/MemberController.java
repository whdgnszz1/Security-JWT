package com.example.securityjwttemplate.member;

import com.example.securityjwttemplate.member.request.LoginRequest;
import com.example.securityjwttemplate.member.request.SignupRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class MemberController {
    private final MemberService service;

    @PostMapping("/signup")
    public ResponseEntity<MemberEntity> signup(@RequestBody SignupRequest request) {
        MemberEntity createdMember = service.signup(request.getUsername(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(createdMember);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        String token = service.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(token);
    }
}
