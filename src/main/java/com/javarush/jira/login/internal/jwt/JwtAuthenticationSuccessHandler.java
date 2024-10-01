package com.javarush.jira.login.internal.jwt;

import com.javarush.jira.login.AuthUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static com.javarush.jira.login.internal.jwt.JwtService.JWT_COOKIE_NAME;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        Object principal = authentication.getPrincipal();
        AuthUser authUser = (principal instanceof AuthUser au) ? au : null;
        if (authUser != null) {
            String jwtToken = jwtService.generateToken(authUser);
            Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, jwtToken);
            jwtCookie.setPath("/");
            response.addCookie(jwtCookie);
        }
        response.sendRedirect("/");
    }
}
