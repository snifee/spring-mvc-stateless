package org.snifee.controller.login;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.snifee.config.AuthProvider;
import org.snifee.config.JwtComponent;
import org.snifee.model.LoginForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

@Slf4j
@Controller
public class LoginController {

    @Autowired
    private AuthProvider authenticationProvider;

    @Autowired
    private UserDetailsService userDetailsService;


    @Autowired
    private JwtComponent jwtComponent;

    /** Login form. */
    @RequestMapping("/login")
    public String login(Model model) {
        model.addAttribute("loginForm", new LoginForm());
        return "login";
    }

    /** Login form with error. */
    @RequestMapping("/login-error")
    public String loginError(Model model) {
        model.addAttribute("loginError", Boolean.TRUE);
        return "login";
    }


    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public void authenticate(@ModelAttribute("loginForm")LoginForm loginForm, HttpServletRequest request, HttpServletResponse response){

        try{

            UserDetails user = userDetailsService.loadUserByUsername(loginForm.getUsername());

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    loginForm.getUsername(),
                    loginForm.getPassword(),
                    user.getAuthorities()
            );

            Authentication auth = authenticationProvider.authenticate(token);

            if (auth!=null){
                Map<String, Object> claims = new HashMap<>();
                claims.put("ROLE", user.getAuthorities());

                String jwtToken = jwtComponent.generateAccessToken(user.getUsername(), claims);
                Date expires = jwtComponent.extractExpiration(jwtToken);
                Cookie jwtTokencCookie = new Cookie("jwt_access_token", jwtToken);
                jwtTokencCookie.setHttpOnly(true);
                jwtTokencCookie.setSecure(request.isSecure());
                jwtTokencCookie.setPath(request.getContextPath());
                jwtTokencCookie.setMaxAge(15*60);
                response.addCookie(jwtTokencCookie);
                response.sendRedirect("/index.html");
            }
        }catch (Exception e){
            log.error(e.getMessage());
        }
    }
}
