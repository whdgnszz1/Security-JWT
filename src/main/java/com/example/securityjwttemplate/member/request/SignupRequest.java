package com.example.securityjwttemplate.member.request;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignupRequest {
    private String username;
    private String password;
}
