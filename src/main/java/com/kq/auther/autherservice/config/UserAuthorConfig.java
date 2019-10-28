package com.kq.auther.autherservice.config;

import com.kq.auther.autherservice.entryPoint.JwtAuthenticationEntryPoint;
import com.kq.auther.autherservice.filter.JwtAuthenticationTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class UserAuthorConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Value("$(author.token.user.secret)")
    private String sercret;

    @Value("$(author.token.ValidityInMilliseconds)")
    private long tokenValidityInMilliseconds;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests().
                // exception handler
                and().exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).
                //we use jwt, session is not necessary
                and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(new JwtAuthenticationTokenFilter(sercret,tokenValidityInMilliseconds),
                UsernamePasswordAuthenticationFilter.class);
        // disable hearder cache
        http.headers().cacheControl().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
