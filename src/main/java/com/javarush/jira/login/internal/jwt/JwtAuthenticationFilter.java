package com.javarush.jira.login.internal.jwt;

import com.javarush.jira.login.User;
import com.javarush.jira.login.internal.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import static org.apache.commons.lang3.StringUtils.isNotEmpty;


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

        HttpSession session = request.getSession();
        String jwtToken = (String) session.getAttribute("JwtToken");

        if (isNotEmpty(jwtToken)) {
            SecurityContext securityContext = SecurityContextHolder.getContext();
            String email = jwtService.extractUserName(jwtToken);

            if (isNotEmpty(email) && securityContext.getAuthentication() == null ) {
                Optional<User> optionalUser = userRepository.findByEmailIgnoreCase(email);
                if (optionalUser.isPresent() && jwtService.isTokenValid(jwtToken, optionalUser.get())) {
                    User user = optionalUser.get();
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(authToken);
                }
            }
        } else {

        }

        filterChain.doFilter(request, response);
    }
}
