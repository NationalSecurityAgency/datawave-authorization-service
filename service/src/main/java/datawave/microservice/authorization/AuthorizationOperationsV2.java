package datawave.microservice.authorization;

import datawave.microservice.authorization.config.AuthorizationsListSupplier;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.microservice.security.util.DnUtils;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.bus.BusProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

/**
 * Presents the REST operations for the authorization service. This version returns the updated (V2) DatawaveUser
 */
@RestController
@RequestMapping(path = "/v2", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthorizationOperationsV2 extends AuthorizationOperationsV1 {
    
    @Autowired
    public AuthorizationOperationsV2(JWTTokenHandler tokenHandler, CachedDatawaveUserService cachedDatawaveUserService, ApplicationContext appCtx,
                    BusProperties busProperties, AuthorizationsListSupplier authorizationsListSupplier, DnUtils dnUtils) {
        super(tokenHandler, cachedDatawaveUserService, appCtx, busProperties, authorizationsListSupplier, dnUtils);
    }
    
    // If there are any proxied users, exclude the last caller from the returned ProxiedUserDetails
    // If there is only one user, return the provided ProxiedUserDetails unchanged
    private ProxiedUserDetails transformCurrentUser(ProxiedUserDetails currentUser) {
        int numUsers = currentUser.getProxiedUsers().size();
        if (numUsers == 1) {
            return currentUser;
        } else {
            return new ProxiedUserDetails(currentUser.getProxiedUsers().stream().limit(numUsers - 1).collect(Collectors.toList()),
                            currentUser.getCreationTime());
        }
    }
    
    @Operation(summary = "Returns a JWT of the current user/proxied user(s)",
                    description = "The returned JWT can be passed to other calls in a header. For example: \"Authorization: Bearer <JWT value>\".\n"
                                    + "The JWT is created from the proxied users if present or from the supplied client certificate "
                                    + "or trusted headers (X-SSL-clientcert-subject/X-SSL-clientcert-issuer) if there are no proxied users.")
    @RequestMapping(path = "/authorize", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE}, method = RequestMethod.GET)
    public String user(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        ProxiedUserDetails transformedUser = transformCurrentUser(currentUser);
        return tokenHandler.createTokenFromUsers(transformedUser.getUsername(), transformedUser.getProxiedUsers());
    }
    
    /**
     * Returns the {@link ProxiedUserDetails} that represents the authenticated calling user.
     */
    @Operation(summary = "Returns details about the current user/proxied user(s).",
                    description = "The user(s) can be determined from the proxied user(s) if present or from the supplied client certificate "
                                    + "or trusted headers (X-SSL-clientcert-subject/X-SSL-clientcert-issuer) if there are no proxied users.")
    @RequestMapping(path = "/whoami", method = RequestMethod.GET)
    public ProxiedUserDetails hello(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        return transformCurrentUser(currentUser);
    }
    
    /**
     * Lists the user, if any, contained in the authentication cache and having a {@link DatawaveUser#getName()} of name.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @param username
     *            the name of the user to list
     * @return the cached user whose {@link DatawaveUser#getName()} is name, or null if no such user is cached
     * @see CachedDatawaveUserService#list(String)
     */
    @Operation(summary = "Lists the details for the named cached user.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUser", method = RequestMethod.GET)
    public DatawaveUser listCachedUser(@Parameter(description = "The username (e.g., subjectDn<issuerDn>) to evict") @RequestParam String username) {
        return cachedDatawaveUserService.list(username);
    }
}
