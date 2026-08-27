package org.snifee.config;

import org.snifee.model.enums.Roles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserDetailServiceConfig {

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails jim = User.builder()
                .username("jim")
                .password(passwordEncoder().encode("demo"))
                .roles(Roles.ADMIN.name())
//                .authorities(new SimpleGrantedAuthority(Roles.ADMIN.name()))
                .build();

        UserDetails bob = User.builder()
                .username("bob")
                .password(passwordEncoder().encode("demo"))
                .roles(Roles.USER.name())
//                .authorities(new SimpleGrantedAuthority(Roles.USER.name()))
                .build();

        UserDetails ted = User.builder()
                .username("ted")
                .password(passwordEncoder().encode("demo"))
                .roles(Roles.USER.name(),Roles.ADMIN.name())
//                .authorities(
//                        new SimpleGrantedAuthority(Roles.USER.name()),
//                        new SimpleGrantedAuthority(Roles.ADMIN.name())
//                )
                .build();

        return new InMemoryUserDetailsManager(jim, ted, bob);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
