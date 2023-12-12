package com.pjh.refreshtoken.auth.controller;

import com.pjh.refreshtoken.auth.service.AuthService;
import com.pjh.refreshtoken.global.CommonResponseDto;
import com.pjh.refreshtoken.member.dto.SignupDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AuthController {

    private final AuthService authService;

    @PostMapping("/auth/signup")
    public ResponseEntity<CommonResponseDto<?>> signup(@RequestBody SignupDto signupDto){
        CommonResponseDto<?> cmRDto = authService.signup(signupDto);
        return new ResponseEntity<>(cmRDto, HttpStatus.valueOf(cmRDto.getStatusCode()));
    }
}
