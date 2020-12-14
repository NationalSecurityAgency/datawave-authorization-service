package datawave.microservice.authorization.config;

import datawave.microservice.config.security.AllowedCallersFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

public class AuthorizationAllowedCallersFilter extends AllowedCallersFilter {
    private static final Pattern oauthPattern = Pattern.compile("/v\\d*/oauth/.*");
    
    public AuthorizationAllowedCallersFilter(DatawaveSecurityProperties securityProperties, AuthenticationEntryPoint authenticationEntryPoint) {
        super(securityProperties, authenticationEntryPoint);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain)
                    throws ServletException, IOException {
        
        if (AuthorizationAllowedCallersFilter.enforceAllowedCallersForRequest(httpServletRequest)) {
            super.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
        } else {
            // Continue the chain to handle any other filters
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }
    }
    
    public static boolean enforceAllowedCallersForRequest(HttpServletRequest httpServletRequest) {
        return !oauthPattern.matcher(httpServletRequest.getServletPath()).matches();
    }
}
