package com.pjh.refreshtoken.jwt;

import com.pjh.refreshtoken.member.dto.TokenDto;
import com.pjh.refreshtoken.member.entity.MemberRoleEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtProvider {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String REFRESH_TOKEN_HEADER = "RefreshToken";
    public static final String AUTHORIZATION_KEY = "auth";
    public static final String BEARER_PREFIX = "Bearer ";
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    private static final Long ACCESS_TOKEN_TIME = 60 * 60 * 1000L;
    private static final Long REFRESH_TOKEN_TIME = 14 * 24 * 60 * 60 * 1000L;

    @Value("${jwt.secret.key}")
    private String secretKey;
    private Key key;

    @PostConstruct
    public void init(){
        log.info("init start!");
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    public TokenDto createToken(String username, MemberRoleEnum role){
        log.info("토큰 생성");
        Date date = new Date();

        String accessToken = BEARER_PREFIX + Jwts.builder()
                .setSubject(username)
                .claim(AUTHORIZATION_KEY,role)
                .setExpiration(new Date(date.getTime()+ACCESS_TOKEN_TIME))
                .setIssuedAt(date)
                .signWith(key, signatureAlgorithm)
                .compact();

        String refreshToken = BEARER_PREFIX + Jwts.builder()
                .setSubject(username)
                .claim(AUTHORIZATION_KEY, role)
                .setIssuedAt(date)
                .setExpiration(new Date(date.getTime()+REFRESH_TOKEN_TIME))
                .signWith(key, signatureAlgorithm)
                .compact();

        return TokenDto.of(accessToken, refreshToken);
    }

    public String getJwtFromHeader(HttpServletRequest req){
        log.info("getJwtFromHeader()");
        String bearerToken = req.getHeader(AUTHORIZATION_HEADER);
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)){
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            log.info("validateToken");
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException | io.jsonwebtoken.security.SignatureException e) {
            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    // JWT 사용자 정보를 가져오기
    public Claims getUserInfoFromToken(String tokenValue) {
        log.info("getUserInfoFromToken");
        // 새로운 객체에 secretKey encode한거 payload에 넣고 Jws(tokenValue)넣기
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(tokenValue)
                .getBody();
    }

    public void setTokenResponse(TokenDto tokenDto, HttpServletResponse res){
        setHeaderAccessToken(tokenDto.getAccessToken(), res);
        setCookieRefreshToken(tokenDto.getRefreshToken(), res);
    }

    private void setHeaderAccessToken(String accessToken, HttpServletResponse res){
        res.setHeader(AUTHORIZATION_HEADER, BEARER_PREFIX+ accessToken);
    }

    private void setCookieRefreshToken(String refreshToken, HttpServletResponse res){
        refreshToken = URLEncoder.encode(BEARER_PREFIX + refreshToken, StandardCharsets.UTF_8).replaceAll("\\+", "%20");

        // Cookie는 hashMap형태
        Cookie cookie = new Cookie(REFRESH_TOKEN_HEADER, refreshToken);
        // Cookie(String name, value) -> 위에 clonable이 name 검증해줌
        // AccessToken이 Authorization : Bearer ~~~~가 나오듯

        // cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        // RefreshToken은 RefreshToken : Bearer로 HttpServletResponse res에 cookie를 더해서 가져감
        res.addCookie(cookie);
    }

    // RefreshToken에서도 우리의 정보를 가져올 수 있음
    // 당연하지만 AccessToken도 마찬가지임
    // 이유는 jwt Token으로 만들었으니 setSubject(username || email)이 들어가있고
    // Claims에 우리의 정보인 role이 들어갔기에
    public String getRefreshTokenFromCookie(HttpServletRequest req){
        Cookie[] cookies = req.getCookies();

        if(cookies == null){
            return null;
        }
        String token = "";
        for(Cookie cookie : cookies){
            if(cookie.getName().equals(REFRESH_TOKEN_HEADER)){
                token = URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
            }
        }
        return token.substring(7);
    }
}
