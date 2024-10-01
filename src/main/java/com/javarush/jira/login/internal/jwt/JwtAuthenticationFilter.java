package com.javarush.jira.login.internal.jwt;

import com.javarush.jira.login.User;
import com.javarush.jira.login.internal.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;
import static com.javarush.jira.login.internal.jwt.JwtService.JWT_COOKIE_NAME;


@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String jwtToken = "";

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            jwtToken = (Arrays.stream(request.getCookies())
                    .filter(cookie -> JWT_COOKIE_NAME.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()).orElse("");
        }

        if (isNotEmpty(jwtToken)) {
            SecurityContext securityContext = SecurityContextHolder.getContext();
            String email = jwtService.extractEmail(jwtToken);

            if (isNotEmpty(email) && "anonymousUser".equals(securityContext.getAuthentication().getPrincipal())) {
                Optional<User> optionalUser = userRepository.findByEmailIgnoreCase(email);
                if (optionalUser.isPresent() && jwtService.isTokenValid(jwtToken, optionalUser.get())) {
                    User user = optionalUser.get();
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getRoles());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(authToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
