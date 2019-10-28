package com.kq.auther.autherservice.filter;

import com.kq.auther.autherservice.Util.AuthorConstant;
import com.kq.auther.autherservice.Util.JwtTokenUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private static final String TOKEN_PREFIX = "Bearer ";

    private String secretKey;
    private long tokenValidityInMilliseconds;

    public JwtAuthenticationTokenFilter(String secretKey,long tokenValidityInMilliseconds) {
        this.secretKey = secretKey;
        this.tokenValidityInMilliseconds = tokenValidityInMilliseconds;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String jwt = resolveToken(request);

        if (jwt != null && !"".equals(jwt.trim()) && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (JwtTokenUtils.validateToken(jwt,secretKey)) {
                /**
                 * get auth info
                 */
                Authentication authentication = JwtTokenUtils.getAuthentication(jwt,secretKey);
                /**
                 * save user info to securityContext
                 */
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Get token from header
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AuthorConstant.AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(7, bearerToken.length());
        }
        String jwt = request.getParameter(AuthorConstant.AUTHORIZATION_TOKEN);
        if (StringUtils.hasText(jwt)) {
            return jwt;
        }
        return null;
    }
}
