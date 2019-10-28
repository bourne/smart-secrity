package com.kq.auther.autherservice.provider;

import com.kq.auther.autherservice.Service.SmartUserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * 结合userDetail实现权限认证
 */
@Component
public class SmartAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private SmartUserDetailsServiceImpl userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!password.equals(userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, null, null);
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }
}
