package datawave.microservice.authorization;

import datawave.microservice.authorization.config.AuthorizationsListSupplier;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.microservice.security.util.DnUtils;
import datawave.security.DnList;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserInfo;
import datawave.security.authorization.DatawaveUserV1;
import datawave.security.authorization.JWTTokenHandler;
import datawave.user.AuthorizationsListBase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.bus.BusProperties;
import org.springframework.cloud.bus.event.AuthorizationEvictionEvent;
import org.springframework.cloud.bus.event.AuthorizationEvictionEvent.Type;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import static datawave.microservice.http.converter.protostuff.ProtostuffHttpMessageConverter.PROTOSTUFF_VALUE;
import static org.springframework.web.accept.ContentNegotiationStrategy.MEDIA_TYPE_ALL_LIST;

/**
 * Presents the REST operations for the authorization service. This version returns a DatawaveUserV1 individually and when encapsulated by a ProxiedUserDetails
 * to avoid serialization errors in clients that have not been updated
 */
@RestController
@RequestMapping(path = "/v1", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthorizationOperationsV1 {
    private final Logger log = LoggerFactory.getLogger(AuthorizationOperationsV1.class);
    
    protected final JWTTokenHandler tokenHandler;
    protected final CachedDatawaveUserService cachedDatawaveUserService;
    protected final ApplicationContext appCtx;
    protected final BusProperties busProperties;
    
    protected final AuthorizationsListSupplier authorizationsListSupplier;
    
    protected final DnUtils dnUtils;
    
    @Autowired
    public AuthorizationOperationsV1(JWTTokenHandler tokenHandler, CachedDatawaveUserService cachedDatawaveUserService, ApplicationContext appCtx,
                    BusProperties busProperties, AuthorizationsListSupplier authorizationsListSupplier, DnUtils dnUtils) {
        this.tokenHandler = tokenHandler;
        this.cachedDatawaveUserService = cachedDatawaveUserService;
        this.appCtx = appCtx;
        this.busProperties = busProperties;
        this.authorizationsListSupplier = authorizationsListSupplier;
        this.dnUtils = dnUtils;
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
    
    @Operation(summary = "Returns a JWT of the current user/proxied user(s)",
                    description = "The returned JWT can be passed to other calls in a header. For example: \"Authorization: Bearer <JWT value>\".\n"
                                    + "The JWT is created from the proxied users if present or from the supplied client certificate "
                                    + "or trusted headers (X-SSL-clientcert-subject/X-SSL-clientcert-issuer) if there are no proxied users.")
    @RequestMapping(path = "/authorize", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE}, method = RequestMethod.GET)
    public String user(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        ProxiedUserDetails transformedUser = transformCurrentUser(currentUser);
        return tokenHandler.createTokenFromUsers(transformedUser.getUsername(), transformedUser.getProxiedUsers());
    }
    
    @Operation(summary = "Lists the effective Accumulo user authorizations for the calling user.")
    @RequestMapping(path = "/listEffectiveAuthorizations", method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE,
            MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_XML_VALUE, PROTOSTUFF_VALUE, MediaType.TEXT_HTML_VALUE, "text/x-yaml", "application/x-yaml"})
    public AuthorizationsListBase<?> listEffectiveAuthorizations(@AuthenticationPrincipal ProxiedUserDetails currentUser) {
        final AuthorizationsListBase<?> list = authorizationsListSupplier.get();
        
        // Find out who/what called this method
        String name = dnUtils.getShortName(currentUser.getPrimaryUser().getName());
        
        // Add the user DN's auths into the authorization list
        DatawaveUser primaryUser = currentUser.getPrimaryUser();
        list.setUserAuths(primaryUser.getDn().subjectDN(), primaryUser.getDn().issuerDN(), new HashSet<>(primaryUser.getAuths()));
        
        // Now add all entity auth sets into the list
        currentUser.getProxiedUsers().forEach(u -> list.addAuths(u.getDn().subjectDN(), u.getDn().issuerDN(), new HashSet<>(u.getAuths())));
        
        // Add the role to authorization mapping.
        // NOTE: Currently this is only added for the primary user, which is really all anyone should care about in terms of mucking with
        // authorizations. When used for queries, all non-primary users have all of their auths included -- there is no downgrading.
        list.setAuthMapping(currentUser.getPrimaryUser().getRoleToAuthMapping().asMap());
        log.trace(name + " has authorizations union " + list.getAllAuths());
        return list;
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
     * Evicts the user identified by the {@link DatawaveUser#getName()} of username from the authentication cache.
     * <p>
     * Note that access to this method is restricted to those users with administrative credentials.
     *
     * @param username
     *            the name of the user to evict
     * @return status indicating whether or not any users were evicted from the authentication cache
     * @see CachedDatawaveUserService#evict(String)
     */
    @Operation(summary = "Evicts the named user from the authorization cache.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/evictUser", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE},
                    method = {RequestMethod.GET, RequestMethod.DELETE})
    public String evictUser(@Parameter(description = "The username (e.g., subjectDn<issuerDn>) to evict") @RequestParam String username) {
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
    @Operation(summary = "Evicts from the authorization cache all users whose name contains the supplied substring.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/evictUsersMatching", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_JSON_VALUE},
                    method = {RequestMethod.GET, RequestMethod.DELETE})
    public String evictUsersMatching(@Parameter(description = "A substring to search for in user names to evict") @RequestParam String substring) {
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
    @Operation(summary = "Evicts all users from the authorization cache.")
    @Secured({"Administrator", "JBossAdministrator"})
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
    @Operation(summary = "Lists the details for the named cached user.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUser", method = RequestMethod.GET)
    public DatawaveUser listCachedUser(@Parameter(description = "The username (e.g., subjectDn<issuerDn>) to evict") @RequestParam String username) {
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
    @Operation(summary = "Retrieves details for all cached users whose names match a substring.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUsersMatching", method = RequestMethod.GET)
    public Collection<? extends DatawaveUserInfo> listCachedUsersMatching(
                    @Parameter(description = "A substring to search for in user names to list") @RequestParam String substring) {
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
    @Operation(summary = "Retrieves details for all cached users.")
    @Secured({"Administrator", "JBossAdministrator"})
    @RequestMapping(path = "/admin/listUsers", method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE,
            MediaType.TEXT_XML_VALUE, PROTOSTUFF_VALUE, MediaType.TEXT_HTML_VALUE, "text/x-yaml", "application/x-yaml"})
    public Object listCachedUsers(@RequestHeader HttpHeaders headers) {
        Collection<? extends DatawaveUserInfo> dnList = cachedDatawaveUserService.listAll();
        
        MediaType preferredMediaType = determinePreferredMediaType(headers.getAccept());
        if (preferredMediaType.equals(MediaType.TEXT_HTML)) {
            return new DnList(dnList);
        } else {
            return dnList;
        }
    }
    
    private MediaType determinePreferredMediaType(List<MediaType> mediaTypes) {
        mediaTypes = !CollectionUtils.isEmpty(mediaTypes) ? mediaTypes : MEDIA_TYPE_ALL_LIST;
        MediaType.sortBySpecificityAndQuality(mediaTypes);
        return mediaTypes.get(0);
    }
}
