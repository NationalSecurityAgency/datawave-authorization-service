package datawave.microservice.authorization.oauth;

import datawave.microservice.authorization.user.ProxiedUserDetails;

import java.io.Serializable;

public class AuthorizationRequest implements Serializable {
    
    private ProxiedUserDetails proxiedUserDetails;
    private AuthorizedClient authorizedClient;
    private String redirect_uri;
    
    public AuthorizationRequest(ProxiedUserDetails proxiedUserDetails, AuthorizedClient authorizedClient, String redirect_uri) {
        this.proxiedUserDetails = proxiedUserDetails;
        this.authorizedClient = authorizedClient;
        this.redirect_uri = redirect_uri;
    }
    
    public ProxiedUserDetails getProxiedUserDetails() {
        return proxiedUserDetails;
    }
    
    public void setProxiedUserDetails(ProxiedUserDetails proxiedUserDetails) {
        this.proxiedUserDetails = proxiedUserDetails;
    }
    
    public void setAuthorizedClient(AuthorizedClient authorizedClient) {
        this.authorizedClient = authorizedClient;
    }
    
    public AuthorizedClient getAuthorizedClient() {
        return authorizedClient;
    }
    
    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }
    
    public String getRedirect_uri() {
        return redirect_uri;
    }
}
