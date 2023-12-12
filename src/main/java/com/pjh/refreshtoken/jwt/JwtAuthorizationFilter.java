package com.pjh.refreshtoken.jwt;

import com.pjh.refreshtoken.security.MemberDetailsServiceImpl;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j(topic = "JWT 검증 및 인가")
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtUtil;
    private final MemberDetailsServiceImpl memberDetailsService;

    public JwtAuthorizationFilter(JwtProvider jwtUtil, MemberDetailsServiceImpl memberDetailsService) {
        this.jwtUtil = jwtUtil;
        this.memberDetailsService = memberDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws ServletException, IOException {
        log.info("doFilterInternal()");
        String tokenValue = jwtUtil.getJwtFromHeader(req);
        log.info("tokenValue : "+tokenValue);
        // 여기 null
        if (StringUtils.hasText(tokenValue)) {
            if (!jwtUtil.validateToken(tokenValue)) {
                log.error("Token Error");
                return;
            }
            Claims info = jwtUtil.getUserInfoFromToken(tokenValue);
            try {
                setAuthentication(info.getSubject());
            } catch (Exception e) {
                log.error(e.getMessage());
                return;
            }
        }
        // 아 진훈님꺼는 doFilter의 다음 설정 필터가 없는거네?
        filterChain.doFilter(req, res);
    }

    // 인증 처리
    public void setAuthentication(String username) {
        log.info("setAuthentication()");
        // 새로운 시큐리티 context를 만듦
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        // SecurityContextHolder안에 존재하는 Authentication에 createAuthentication(username)을 하여
        // 해당 인증 객체에 username에 넣어줍니다.
        Authentication authentication = createAuthentication(username);
        // contextHolder에 인증 객체를 넣어줌
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    // 인증 객체 생성
    private Authentication createAuthentication(String username) {
        log.info("createAuthentication()");
        UserDetails userDetails = memberDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}