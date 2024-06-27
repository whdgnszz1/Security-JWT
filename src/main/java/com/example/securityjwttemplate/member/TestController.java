package com.example.securityjwttemplate.member;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class TestController {
    @GetMapping("/api/test")
    public ResponseEntity<?> test(@AuthenticationPrincipal UserDetails userDetails) {
        log.info("username: " + userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
