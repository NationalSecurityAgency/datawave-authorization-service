package datawave.microservice.authorization.oauth;

import datawave.microservice.authorization.user.DatawaveUserDetails;

import java.io.Serializable;

public class AuthorizationRequest implements Serializable {
    
    private DatawaveUserDetails DatawaveUserDetails;
    private AuthorizedClient authorizedClient;
    private String redirect_uri;
    
    public AuthorizationRequest(DatawaveUserDetails DatawaveUserDetails, AuthorizedClient authorizedClient, String redirect_uri) {
        this.DatawaveUserDetails = DatawaveUserDetails;
        this.authorizedClient = authorizedClient;
        this.redirect_uri = redirect_uri;
    }
    
    public DatawaveUserDetails getDatawaveUserDetails() {
        return DatawaveUserDetails;
    }
    
    public void setDatawaveUserDetails(DatawaveUserDetails DatawaveUserDetails) {
        this.DatawaveUserDetails = DatawaveUserDetails;
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
