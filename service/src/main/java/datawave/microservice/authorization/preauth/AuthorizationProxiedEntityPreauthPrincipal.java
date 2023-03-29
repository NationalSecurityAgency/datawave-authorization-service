package datawave.microservice.authorization.preauth;

import datawave.security.authorization.SubjectIssuerDNPair;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

public class AuthorizationProxiedEntityPreauthPrincipal extends ProxiedEntityPreauthPrincipal {
    
    private HttpServletRequest request;
    
    public AuthorizationProxiedEntityPreauthPrincipal(SubjectIssuerDNPair callerPrincipal, Collection<SubjectIssuerDNPair> proxiedEntities,
                    HttpServletRequest request) {
        super(callerPrincipal, proxiedEntities);
        this.request = request;
    }
    
    public HttpServletRequest getRequest() {
        return request;
    }
}
