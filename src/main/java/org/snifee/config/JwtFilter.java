package org.snifee.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtComponent jwtComponent;

    @Autowired
    private UserDetailsService userDetailsService;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final List<String> excludeUrl = List.of(
            "/login",
            "/authenticate",
            "/css/**",
            "/favicon.ico"
    );

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        return excludeUrl
                .stream()
                .anyMatch(pattern -> pathMatcher.match(pattern,path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info(request.getRequestURI());

        List<Cookie> cookies = List.of(request.getCookies());
        Cookie jwtCookie = cookies.stream()
                .filter(cookie -> "jwt_access_token".equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        if (jwtCookie==null){
            response.sendRedirect("/login");
            return;
        }

        log.info("jwt_cookie found: "+ jwtCookie.getName());

        String jwtToken = jwtCookie.getValue();
        String tokenUsername = jwtComponent.extractUsername(jwtToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(tokenUsername);
        boolean isTokenValid = jwtComponent.validateToken(jwtToken, userDetails);
        boolean isExpired = jwtComponent.isTokenExpired(jwtToken);
        log.info("is token valid: "+isTokenValid);
        if (isTokenValid){
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails.getUsername(),
                    "[PROTECTED]",
                    userDetails.getAuthorities()
            );

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticationToken);
            SecurityContextHolder.setContext(context);
            filterChain.doFilter(request, response);
            return;
        }
        if (isExpired) {
            Cookie jwtRefreshTokenCookie = cookies.stream()
                    .filter(cookie -> "jwt_refresh_token".equals(cookie.getName()))
                    .findFirst()
                    .orElse(null);

            if (jwtRefreshTokenCookie!=null){
                String refreshToken = jwtRefreshTokenCookie.getValue();

                boolean isValid = jwtComponent.validateRefreshToken(refreshToken, userDetails);

                if (isValid) {
                    Map<String, Object> claims = new HashMap<>();
                    claims.put("ROLE", userDetails.getAuthorities());

                    String newJwtAccessToken = jwtComponent.generateAccessToken(userDetails.getUsername(), claims);
                    Cookie newJwtAccessTokenCookie = new Cookie("jwt_access_token", newJwtAccessToken);
                    newJwtAccessTokenCookie.setSecure(true);
                    newJwtAccessTokenCookie.setHttpOnly(true);
                    response.addCookie(newJwtAccessTokenCookie);

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails.getUsername(),
                            "[PROTECTED]",
                            userDetails.getAuthorities()
                    );

                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(authenticationToken);
                    SecurityContextHolder.setContext(context);

                    filterChain.doFilter(request, response);
                    return;
                }
            }

        }
        response.sendRedirect("/login");
    }
}
