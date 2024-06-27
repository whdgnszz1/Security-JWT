package com.example.securityjwttemplate.member;

import com.example.securityjwttemplate.jwt.JwtUtil;
import com.example.securityjwttemplate.member.domain.MemberEntity;
import com.example.securityjwttemplate.member.request.LoginRequest;
import com.example.securityjwttemplate.member.request.SignupRequest;
import com.example.securityjwttemplate.security.UserDetailsImpl;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

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
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        Map<String, String> tokens = service.login(request.getUsername(), request.getPassword());

        // 액세스 토큰 쿠키 설정
        Cookie accessTokenCookie = new Cookie("accessToken", Base64.getUrlEncoder().encodeToString(tokens.get("accessToken").getBytes()));
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true); // HTTPS에서만 전송되도록 설정
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(60 * 60); // 1시간 유효

        // 응답에 쿠키 추가
        response.addCookie(accessTokenCookie);

        // 응답 헤더에 액세스 토큰 추가
        HttpHeaders headers = new HttpHeaders();
        headers.add(JwtUtil.AUTHORIZATION_HEADER, tokens.get("accessToken"));

        return ResponseEntity.ok().headers(headers).body(tokens);
    }

    @GetMapping("/me")
    public ResponseEntity<MemberEntity> getUserInfo(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        MemberEntity member = userDetails.getMember();
        return ResponseEntity.ok(member);
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/admin")
    public ResponseEntity<MemberEntity> getAdminInfo(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        MemberEntity member = userDetails.getMember();
        return ResponseEntity.ok(member);
    }
}
