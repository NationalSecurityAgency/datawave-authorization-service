package datawave.microservice.authorization;

import datawave.microservice.authorization.config.AuthorizationsListSupplier;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.microservice.security.util.DnUtils;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
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
    
    @ApiOperation(value = "Authorizes the calling user to produce a JWT value",
                    notes = "The returned JWT can be passed to other calls in a header. For example: \"Authorization: bearer <JWT value>\".\n"
                                    + "The user can be determined with from the supplied client certificate or trusted headers ("
                                    + "X-SSL-clientcert-subject/X-SSL-clientcert-issuer).")
    @RequestMapping(path = "/authorize", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE}, method = RequestMethod.GET)
    public String user(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        return tokenHandler.createTokenFromUsers(currentUser.getUsername(), currentUser.getProxiedUsers());
    }
    
    /**
     * Returns the {@link ProxiedUserDetails} that represents the authenticated calling user.
     */
    @ApiOperation(value = "Returns details about the current user/proxied users.",
                    notes = "The user can be determined with from the supplied client certificate or trusted headers ("
                                    + "X-SSL-clientcert-subject/X-SSL-clientcert-issuer). Proxied user headers (X-ProxiedEntitiesChain/X-ProxiedIssuersChain) "
                                    + "are also used to determine proxied users to include in the returned details.")
    @RequestMapping(path = "/whoami", method = RequestMethod.GET)
    public ProxiedUserDetails hello(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        return currentUser;
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
    @ApiOperation("Lists the details for the named cached user.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUser", method = RequestMethod.GET)
    public DatawaveUser listCachedUser(@ApiParam("The username (e.g., subjectDn<issuerDn>) to evict") @RequestParam String username) {
        return cachedDatawaveUserService.list(username);
    }
}
