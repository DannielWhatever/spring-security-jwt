package cl.foxblue.commons.spring.security.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 * Bean filter for JWT Authentication,
 * read the jwt token in headers and try to authenticate.
 *
 * @author daniel.gutierrez
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final String HEADER_AUTH = "X-Auth";

    @Autowired private JwtService jwtService;
    @Autowired private UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.setAuthenticationManager(authenticationManager);
    }

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authToken = httpRequest.getHeader(HEADER_AUTH);

        if(authToken != null){
            //obtain user of jwt
            JwtUser jwtUser = jwtService.parseToken(authToken);


            String username = jwtUser.getUsername();
            SecurityContext securityContext = SecurityContextHolder.getContext();

            //if is not authenticated, get user details and try to valid
            if (username != null && securityContext.getAuthentication() == null) {

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if (jwtService.validateToken(authToken, userDetails)) {
                    //create authenticated user...
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities());
                    auth.setDetails(new WebAuthenticationDetailsSource()
                            .buildDetails(httpRequest));
                    //...and set.
                    securityContext.setAuthentication(auth);
                }else{
                    log.debug("Fail to validate token for user {}",username);
                }
            }
        }
        chain.doFilter(request, response);
    }



}