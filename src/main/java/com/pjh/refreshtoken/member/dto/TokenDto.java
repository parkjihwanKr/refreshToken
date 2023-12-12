package com.pjh.refreshtoken.member.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@AllArgsConstructor
@Getter
public class TokenDto {
    private String accessToken;
    private String refreshToken;

    public static TokenDto of(String accessToken, String refreshToken){
        return new TokenDto(accessToken, refreshToken);
    }
}
