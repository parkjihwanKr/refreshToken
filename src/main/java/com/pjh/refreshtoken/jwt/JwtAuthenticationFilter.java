package com.pjh.refreshtoken.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pjh.refreshtoken.member.dto.LoginDto;
import com.pjh.refreshtoken.member.entity.MemberRoleEnum;
import com.pjh.refreshtoken.security.MemberDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtProvider jwtProvider;
    public JwtAuthenticationFilter(JwtProvider jwtProvider){
        this.jwtProvider = jwtProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("attemptAuthentication()");
        log.info("request : "+request);
        try {
            LoginDto requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginDto.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            requestDto.getUsername(),
                            requestDto.getPassword(),
                            null
                    )
            );
            // IOException으로 변경해줘야함, 원래 LoginDto를 JSON형태로 바꾸기 위해
            // 해당 내용은 당연히 HttpServletRequest로부터 요청이 들어와서
            // req를 넣어주고 LoginDto.class의 형태로 읽어야함
            // ObjectMapper().readValue(request.getInputStream(),LoginDto.class);
        } catch (IOException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        log.info("successfulAuthentication()");
        String username = ((MemberDetailsImpl) authResult.getPrincipal()).getUsername();
        MemberRoleEnum role = ((MemberDetailsImpl) authResult.getPrincipal()).getMember().getRole();

        // 이런식으로 accessToken처리
        String accessToken = jwtProvider.createToken(username, role).getAccessToken();
        log.info(accessToken);
        String refreshToken = jwtProvider.createToken(username, role).getRefreshToken();
        // 이런식으로 토큰 요청을 header에 accessToken과 refreshToken을 두개를 주면, 검증도 그렇고 oauth login에서도 바꿔야겠네?
        response.setHeader(JwtProvider.AUTHORIZATION_HEADER, accessToken);
        response.setHeader(JwtProvider.REFRESH_TOKEN_HEADER, refreshToken);
        // response.setHeader(); 없을 때 넣어주는데, 중복된 토큰이 있으면 업데이트 해준다.
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }
}