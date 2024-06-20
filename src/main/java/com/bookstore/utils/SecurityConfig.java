package com.bookstore.utils;

import com.bookstore.services.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(){
        return new CustomUserDetailService();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
        auth.setUserDetailsService(userDetailsService());
        auth.setPasswordEncoder(passwordEncoder());
        return auth;
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler(){
        return ((request, response, accessDeniedException) -> response.sendRedirect(request.getContextPath() + "/error/403"));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
            Exception {
        return http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers( "/css/**", "/js/**", "/", "/register",
                                "/error")
                        .permitAll()
                        .requestMatchers( "/books/edit/**", "/books/delete/**", "books/add", "/categories", "/categories/add", "/categories/edit/**", "/categories/delete/**")
                        .hasAnyAuthority("ADMIN")
//                        .requestMatchers("/books", "/books/add")
//                        .hasAnyAuthority("ADMIN", "USER")
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .deleteCookies("JSESSIONID")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )
                .formLogin(formLogin -> formLogin.loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/")
                        .permitAll()
                )
//                .rememberMe(rememberMe -> rememberMe.key("uniqueAndSecret")
//                        .tokenValiditySeconds(86400)
//                        .userDetailsService(userDetailsService())
//                )
//                .exceptionHandling(exceptionHandling ->
//                        exceptionHandling.accessDeniedHandler(customAccessDeniedHandler()))
                .rememberMe(rememberMe -> rememberMe
                        .key("hutech")
                        .rememberMeCookieName("hutech")
                        .tokenValiditySeconds(24 * 60 * 60)
                        .userDetailsService(userDetailsService())  )
                .exceptionHandling(exceptionHandling -> exceptionHandling  .accessDeniedHandler(customAccessDeniedHandler())
                )
                .sessionManagement(sessionManagement -> sessionManagement  .maximumSessions(1) .expiredUrl("/login")  )
                .httpBasic(httpBasic -> httpBasic
                        .realmName("hutech")  )
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .loginPage("/login")
                )
                .build();
    }

}

