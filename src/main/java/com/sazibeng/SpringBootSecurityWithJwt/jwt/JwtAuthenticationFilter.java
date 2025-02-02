package com.sazibeng.SpringBootSecurityWithJwt.jwt;

import com.sazibeng.SpringBootSecurityWithJwt.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;


    public JwtAuthenticationFilter(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {


        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }


        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);

     if(username !=null && SecurityContextHolder.getContext().getAuthentication() == null){
         UserDetails userDetails= userService.loadUserByUsername(username);

        //validate token and user details
         if(jwtService.isValid(token,userDetails)){
             //if token is valid, create authentication token
             UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(
                     userDetails,null, userDetails.getAuthorities()
             );

             authToken.setDetails(
                     new WebAuthenticationDetailsSource().buildDetails(request)
             );

             SecurityContextHolder.getContext().setAuthentication(authToken);

         }

     }

    }
}