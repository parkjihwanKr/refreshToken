package com.pjh.refreshtoken.security;

import com.pjh.refreshtoken.member.entity.Member;
import com.pjh.refreshtoken.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class MemberDetailsServiceImpl implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        Member member = memberRepository.findByUsername(username).orElseThrow(
                ()-> new UsernameNotFoundException("not found : "+username)
        );
        return new MemberDetailsImpl(member);
    }
}
