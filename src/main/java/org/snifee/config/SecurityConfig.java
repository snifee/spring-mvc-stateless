package org.snifee.config;

import org.snifee.model.enums.Roles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity){
        return httpSecurity
            .csrf(Customizer.withDefaults())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> 
                auth
                    .requestMatchers(
                        "/css/**",
                            "/login",
                            "/authenticate",
                            "/static/**"
                    ).permitAll()
                    .requestMatchers("/admin/**").hasRole(Roles.ADMIN.name())
                    .requestMatchers("/user/**").hasRole(Roles.USER.name())
                    .requestMatchers("/shared/**").hasAnyRole(
                            Roles.ADMIN.name(),Roles.USER.name()
                        )
                    .anyRequest().authenticated()
            )
            .exceptionHandling(exception -> 
                exception.accessDeniedPage("/403.html")
            )
            .build();
    }
}
