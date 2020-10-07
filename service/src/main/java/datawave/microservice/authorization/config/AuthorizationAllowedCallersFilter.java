package datawave.microservice.authorization.config;

import datawave.microservice.config.security.AllowedCallersFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

public class AuthorizationAllowedCallersFilter extends AllowedCallersFilter {
    private final Pattern oauthPattern = Pattern.compile("/v\\d*/oauth/.*");
    
    public AuthorizationAllowedCallersFilter(DatawaveSecurityProperties securityProperties) {
        super(securityProperties);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain)
                    throws ServletException, IOException {
        
        String path = httpServletRequest.getServletPath();
        if (!oauthPattern.matcher(path).matches()) {
            super.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
        } else {
            // Continue the chain to handle any other filters
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }
    }
}
