package com.pjh.refreshtoken.auth.service;

import com.pjh.refreshtoken.global.CommonResponseDto;
import com.pjh.refreshtoken.member.dto.SignupDto;
import com.pjh.refreshtoken.member.entity.Member;
import com.pjh.refreshtoken.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    public CommonResponseDto<?> signup(SignupDto signupDto){
        String username = signupDto.getUsername();
        String email = signupDto.getEmail();
        Member duplicateUsernameMember =memberRepository.findByUsername(username).orElse(null);
        if(duplicateUsernameMember != null){
            return new CommonResponseDto<>("해당 유저네임은 존재합니다.", 400);
        }

        Member duplicateEmailMember =memberRepository.findByEmail(email).orElse(null);
        if(duplicateEmailMember != null){
            return new CommonResponseDto<>("해당 이메일은 존재합니다.", 400);
        }

        String rawPassword = signupDto.getPassword();
        String bcrytPassword = passwordEncoder.encode(rawPassword);

        Member memberEntity = Member.builder()
                .username(username)
                .password(bcrytPassword)
                .email(email)
                .build();

        memberRepository.save(memberEntity);

        return new CommonResponseDto<>("회원 가입 성공",400);
    }
}
