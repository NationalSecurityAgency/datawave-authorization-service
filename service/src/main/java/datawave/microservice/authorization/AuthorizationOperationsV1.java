package datawave.microservice.authorization;

import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserInfo;
import datawave.security.authorization.DatawaveUserV1;
import datawave.security.authorization.JWTTokenHandler;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.bus.BusProperties;
import org.springframework.cloud.bus.event.AuthorizationEvictionEvent;
import org.springframework.cloud.bus.event.AuthorizationEvictionEvent.Type;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Presents the REST operations for the authorization service. This version returns a DatawaveUserV1 individually and when encapsulated by a ProxiedUserDetails
 * to avoid serialization errors in clients that have not been updated
 */
@RestController
@RequestMapping(path = "/v1", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthorizationOperationsV1 {
    protected final JWTTokenHandler tokenHandler;
    protected final CachedDatawaveUserService cachedDatawaveUserService;
    protected final ApplicationContext appCtx;
    protected final BusProperties busProperties;
    
    @Autowired
    public AuthorizationOperationsV1(JWTTokenHandler tokenHandler, CachedDatawaveUserService cachedDatawaveUserService, ApplicationContext appCtx,
                    BusProperties busProperties) {
        this.tokenHandler = tokenHandler;
        this.cachedDatawaveUserService = cachedDatawaveUserService;
        this.appCtx = appCtx;
        this.busProperties = busProperties;
    }
    
    // Convert default DatawaveUser (v2) to DatawaveUserV1 for backward compatability of v1 operation
    // If there are any proxied users, exclude the last caller from the returned ProxiedUserDetails
    // If there is only one user, use that user in the returned ProxiedUserDetails
    private ProxiedUserDetails transformCurrentUser(ProxiedUserDetails currentUser) {
        int numUsers = currentUser.getProxiedUsers().size();
        long limit = numUsers == 1 ? 1 : numUsers - 1;
        List<DatawaveUser> proxiedUsersV1 = currentUser.getProxiedUsers().stream().limit(limit).map(u -> new DatawaveUserV1(u)).collect(Collectors.toList());
        return new ProxiedUserDetails(proxiedUsersV1, currentUser.getCreationTime());
    }
    
    @ApiOperation(value = "Returns a JWT of the current user/proxied user(s)",
                    notes = "The returned JWT can be passed to other calls in a header. For example: \"Authorization: Bearer <JWT value>\".\n"
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
    @ApiOperation(value = "Returns details about the current user/proxied user(s).",
                    notes = "The user(s) can be determined from the proxied user(s) if present or from the supplied client certificate "
                                    + "or trusted headers (X-SSL-clientcert-subject/X-SSL-clientcert-issuer) if there are no proxied users.")
    @RequestMapping(path = "/whoami", method = RequestMethod.GET)
    public ProxiedUserDetails hello(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        return transformCurrentUser(currentUser);
    }
    
    /**
     * Evicts the user identified by the {@link DatawaveUser#getName()} of username from the authentication cache.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @param username
     *            the name of the user to evict
     * @return status indicating whether or not any users were evicted from the authentication cache
     * @see CachedDatawaveUserService#evict(String)
     */
    @ApiOperation("Evicts the named user from the authorization cache.")
    @RolesAllowed({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/evictUser", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE},
                    method = {RequestMethod.GET, RequestMethod.DELETE})
    public String evictUser(@ApiParam("The username (e.g., subjectDn<issuerDn>) to evict") @RequestParam String username) {
        appCtx.publishEvent(new AuthorizationEvictionEvent(this, busProperties.getId(), Type.USER, username));
        return cachedDatawaveUserService.evict(username);
    }
    
    /**
     * Evicts all users whose name ({@link DatawaveUser#getName()}) contains the supplied substring from the authentication cache.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @return status indicating whether or not any users were evicted from the authentication cache
     * @see CachedDatawaveUserService#evictMatching(String)
     */
    @ApiOperation("Evicts from the authorization cache all users whose name contains the supplied substring.")
    @RolesAllowed({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/evictUsersMatching", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE},
                    method = {RequestMethod.GET, RequestMethod.DELETE})
    public String evictUsersMatching(@ApiParam("A substring to search for in user names to evict") @RequestParam String substring) {
        appCtx.publishEvent(new AuthorizationEvictionEvent(this, busProperties.getId(), Type.PARTIAL, substring));
        return cachedDatawaveUserService.evictMatching(substring);
    }
    
    /**
     * Evicts all users from the authentication cache.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @return status indicating whether or not any users were evicted from the authentication cache
     * @see CachedDatawaveUserService#evictAll()
     */
    @ApiOperation("Evicts all users from the authorization cache.")
    @RolesAllowed({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/evictAll", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE},
                    method = {RequestMethod.GET, RequestMethod.DELETE})
    public String evictAll() {
        appCtx.publishEvent(new AuthorizationEvictionEvent(this, busProperties.getId(), Type.FULL, null));
        return cachedDatawaveUserService.evictAll();
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
    @RolesAllowed({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUser", method = RequestMethod.GET)
    public DatawaveUser listCachedUser(@ApiParam("The username (e.g., subjectDn<issuerDn>) to evict") @RequestParam String username) {
        DatawaveUser user = cachedDatawaveUserService.list(username);
        return user == null ? null : new DatawaveUserV1(user);
    }
    
    /**
     * Lists the users, if any, contained in the authentication cache and containing substring in their {@link DatawaveUser#getName()}.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @param substring
     *            the sub-string to be contained in all returned users' {@link DatawaveUser#getName()}
     * @return the matching cached users, ifany
     * @see CachedDatawaveUserService#listMatching(String)
     */
    @ApiOperation(value = "Retrieves details for all cached users whose names match a substring.")
    @RolesAllowed({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUsersMatching", method = RequestMethod.GET)
    public Collection<? extends DatawaveUserInfo> listCachedUsersMatching(
                    @ApiParam("A substring to search for in user names to list") @RequestParam String substring) {
        return cachedDatawaveUserService.listMatching(substring);
    }
    
    /**
     * Lists all users stored in the authentication cache.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @return a collection of all {@link DatawaveUser}s that are stored in the authentication cache
     * @see CachedDatawaveUserService#listAll()
     */
    @ApiOperation(value = "Retrieves details for all cached users.")
    @RolesAllowed({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUsers", method = RequestMethod.GET)
    public Collection<? extends DatawaveUserInfo> listCachedUsers() {
        return cachedDatawaveUserService.listAll();
    }
}
