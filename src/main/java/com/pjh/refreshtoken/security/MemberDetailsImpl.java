package com.pjh.refreshtoken.security;

import com.pjh.refreshtoken.member.entity.Member;
import com.pjh.refreshtoken.member.entity.MemberRoleEnum;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class MemberDetailsImpl implements UserDetails {

    private Member member;

    public MemberDetailsImpl(Member member){
        this.member = member;
    }
    public Member getMember(){
        return this.member;
    }

    @Override
    public String getUsername(){
        return this.member.getUsername();
    }

    @Override
    public String getPassword(){
        return this.member.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        MemberRoleEnum role = member.getRole();
        String authority = role.getAuthority();

        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(authority);
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(simpleGrantedAuthority);
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
