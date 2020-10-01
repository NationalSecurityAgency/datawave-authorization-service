package datawave.microservice.authorization;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import datawave.microservice.authorization.jwt.JWTRestTemplate;
import datawave.security.authorization.OAuthTokenResponse;
import datawave.security.authorization.OAuthUserInfo;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.microservice.config.web.RestClientProperties;
import datawave.security.authorization.*;
import datawave.security.util.ProxiedEntityUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheType;
import org.springframework.boot.test.autoconfigure.core.AutoConfigureCache;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.*;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;

import static datawave.security.authorization.DatawaveUser.UserType.SERVER;
import static datawave.security.authorization.DatawaveUser.UserType.USER;
import static datawave.security.authorization.OAuthConstants.*;
import static java.util.stream.Collectors.toList;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "spring.main.allow-bean-definition-overriding=true")
@ActiveProfiles({"OAuthServiceTest"})
public class OAuthOperationsV2Test {
    private static final SubjectIssuerDNPair DN = SubjectIssuerDNPair.of("userDn", "issuerDn");
    
    @LocalServerPort
    private int webServicePort;
    
    @Autowired
    private RestTemplateBuilder restTemplateBuilder;
    
    @Autowired
    private JWTTokenHandler jwtTokenHandler;
    
    @Autowired
    private SSLContext sslContext;
    
    @Autowired
    private RestClientProperties restClientProperties;
    
    private JWTRestTemplate jwtRestTemplate;
    
    private static Map<SubjectIssuerDNPair,DatawaveUser> userMap = new LinkedHashMap<>();
    private final SubjectIssuerDNPair userDN = SubjectIssuerDNPair.of("cn=Test User, ou=testing, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private final SubjectIssuerDNPair serverDN = SubjectIssuerDNPair.of("cn=test.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private final String CLIENT_ID = "123456789";
    private final String CLIENT_SECRET = "secret";
    private final String REDIRECT_URI = "https://localhost/redirect";
    
    @Before
    public void setup() {
        userMap.put(userDN,
                        new DatawaveUser(userDN, USER, null, Arrays.asList("A", "B", "E"), Arrays.asList("AuthorizedUser"), null, System.currentTimeMillis()));
        userMap.put(serverDN, new DatawaveUser(serverDN, SERVER, null, Arrays.asList("A", "B", "C", "D"), Arrays.asList("AuthorizedServer"), null,
                        System.currentTimeMillis()));
        OAuthRestTemplateCustomizer customizer = new OAuthRestTemplateCustomizer(sslContext, restClientProperties);
        // Disable following redirects
        restTemplateBuilder = restTemplateBuilder.additionalCustomizers(customizer);
        jwtRestTemplate = restTemplateBuilder.build(JWTRestTemplate.class);
    }
    
    @Test
    public void TestCodeFlowValid() throws Exception {
        DatawaveUser dwUser = userMap.get(userDN);
        DatawaveUser dwServer = userMap.get(serverDN);
        
        // Application redirects user's browser to the authorize endpoint (redirect not shown)
        // The user calls authorize with own credentials and gets redirected back to the application
        // This test is set up to not follow the redirect so that we can test the response
        String state = "randomstatestring";
        ResponseEntity<String> authorizeEntity = authorize(dwUser, RESPONSE_TYPE_CODE, CLIENT_ID, REDIRECT_URI, state);
        Assert.assertEquals("Expecting a 302 redirect", 302, authorizeEntity.getStatusCode().value());
        List<String> valueList = authorizeEntity.getHeaders().get("Location");
        Assert.assertEquals(1, valueList.size());
        Assert.assertTrue("Redirect location should start with redirect_uri", valueList.get(0).startsWith(REDIRECT_URI));
        
        Map<String,List<String>> queryParams = splitQuery(new URL(valueList.get(0)));
        List<String> stateList = queryParams.get("state");
        Assert.assertEquals(1, stateList.size());
        Assert.assertEquals("If state parameter is send, it should be returned", state, stateList.get(0));
        List<String> codeList = queryParams.get("code");
        Assert.assertEquals(1, codeList.size());
        
        // This is the short-lived code that an application needs to get a user's token
        String code = codeList.get(0);
        
        // After the user's browser gets redirected to the application, the application now has the code
        // and can call the token endpoint to get this user's token
        ResponseEntity<OAuthTokenResponse> tokenEntity = token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, null);
        Assert.assertEquals(200, tokenEntity.getStatusCode().value());
        
        OAuthTokenResponse OAuthTokenResponse = tokenEntity.getBody();
        Assert.assertEquals(200, tokenEntity.getStatusCode().value());
        
        String access_token = OAuthTokenResponse.getAccess_token();
        Collection<DatawaveUser> usersFromToken = jwtTokenHandler.createUsersFromToken(access_token);
        // The DatawaveUser of both the user and the server should be in the token
        // The server is proxying for the user and must also be authenticated
        Assert.assertEquals(2, usersFromToken.size());
        
        // Call the user endpoint with the access_token to get the primary user
        ResponseEntity<OAuthUserInfo> userResponse = user(access_token, JWTTokenHandler.PRINCIPALS_CLAIM);
        OAuthUserInfo OAuthUserInfo = userResponse.getBody();
        Assert.assertEquals(ProxiedEntityUtils.getCommonName(dwUser.getDn().subjectDN()), OAuthUserInfo.getName());
        Assert.assertEquals(dwUser.getLogin(), OAuthUserInfo.getLogin());
        Assert.assertEquals(dwUser.getEmail(), OAuthUserInfo.getEmail());
        Assert.assertEquals(dwUser.getDn(), OAuthUserInfo.getDn());
        Assert.assertEquals(dwUser.getCreationTime(), OAuthUserInfo.getCreationTime());
        
        // Call the users endpoint with the access_token to get the all users
        ResponseEntity<OAuthUserInfo[]> usersResponse = users(access_token, JWTTokenHandler.PRINCIPALS_CLAIM);
        OAuthUserInfo[] users = usersResponse.getBody();
        Assert.assertNotNull(users);
        Assert.assertEquals("Primary and proxying user should be returned", 2, users.length);
        
        // Call the token endpoint with the refresh token id
        String refresh_token = OAuthTokenResponse.getRefresh_token();
        ResponseEntity<OAuthTokenResponse> refreshedTokenEntity = token(dwServer, GRANT_REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET, null, null, refresh_token);
        Assert.assertEquals(200, refreshedTokenEntity.getStatusCode().value());
    }
    
    @Test
    public void TestCodeFlowInvalidClientId() {
        DatawaveUser dwUser = userMap.get(userDN);
        
        // Application redirects user's browser to the authorize endpoint (redirect not shown)
        // The user calls authorize with own credentials and gets redirected back to the application
        // This test is set up to not follow the redirect so that we can test the response
        try {
            authorize(dwUser, RESPONSE_TYPE_CODE, "00000000", REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwUser, GRANT_AUTHORIZATION_CODE, "00000000", CLIENT_SECRET, "wrongcode", REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
    
    @Test
    public void TestCodeFlowMissingResponseType() {
        DatawaveUser dwUser = userMap.get(userDN);
        
        // Application redirects user's browser to the authorize endpoint (redirect not shown)
        // The user calls authorize with own credentials and gets redirected back to the application
        // This test is set up to not follow the redirect so that we can test the response
        try {
            authorize(dwUser, null, CLIENT_ID, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
    
    @Test
    public void TestCodeFlowMissingRedirectUri() {
        DatawaveUser dwUser = userMap.get(userDN);
        
        // Application redirects user's browser to the authorize endpoint (redirect not shown)
        // The user calls authorize with own credentials and gets redirected back to the application
        // This test is set up to not follow the redirect so that we can test the response
        try {
            authorize(dwUser, RESPONSE_TYPE_CODE, CLIENT_ID, null, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
    
    @Test
    public void TestCodeFlowWrongCode() {
        DatawaveUser dwServer = userMap.get(serverDN);
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, "wrongcode", REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
    
    @Test
    public void TestCodeFlowRightCodeWrongOtherParameters() throws Exception {
        DatawaveUser dwUser = userMap.get(userDN);
        DatawaveUser dwServer = userMap.get(serverDN);
        
        // Application redirects user's browser to the authorize endpoint (redirect not shown)
        // The user calls authorize with own credentials and gets redirected back to the application
        // This test is set up to not follow the redirect so that we can test the response
        ResponseEntity<String> authorizeEntity = authorize(dwUser, RESPONSE_TYPE_CODE, CLIENT_ID, REDIRECT_URI, null);
        Assert.assertEquals(302, authorizeEntity.getStatusCode().value());
        List<String> valueList = authorizeEntity.getHeaders().get("Location");
        Assert.assertEquals(1, valueList.size());
        Assert.assertTrue(valueList.get(0).startsWith(REDIRECT_URI));
        
        Map<String,List<String>> queryParams = splitQuery(new URL(valueList.get(0)));
        List<String> codeList = queryParams.get("code");
        Assert.assertEquals(1, codeList.size());
        
        // This is the short-lived code that an application needs to get a user's token
        String code = codeList.get(0);
        
        try {
            token(dwServer, "invalid_grant_type", CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, "invalidClientId", CLIENT_SECRET, code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, "wrongsecret", code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, "https://different_redirect", null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
    
    @Test
    public void TestCodeFlowUseCodeTwice() throws Exception {
        DatawaveUser dwUser = userMap.get(userDN);
        DatawaveUser dwServer = userMap.get(serverDN);
        
        // Application redirects user's browser to the authorize endpoint (redirect not shown)
        // The user calls authorize with own credentials and gets redirected back to the application
        // This test is set up to not follow the redirect so that we can test the response
        ResponseEntity<String> authorizeEntity = authorize(dwUser, RESPONSE_TYPE_CODE, CLIENT_ID, REDIRECT_URI, null);
        Assert.assertEquals(302, authorizeEntity.getStatusCode().value());
        List<String> valueList = authorizeEntity.getHeaders().get("Location");
        Assert.assertEquals(1, valueList.size());
        Assert.assertTrue(valueList.get(0).startsWith(REDIRECT_URI));
        
        Map<String,List<String>> queryParams = splitQuery(new URL(valueList.get(0)));
        List<String> codeList = queryParams.get("code");
        Assert.assertEquals(1, codeList.size());
        
        // This is the short-lived code that an application needs to get a user's token
        String code = codeList.get(0);
        
        // After the user's browser gets redirected to the application, the application now has the code
        // and can call the token endpoint to get this user's token
        ResponseEntity<OAuthTokenResponse> tokenEntity = token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, null);
        Assert.assertEquals(200, tokenEntity.getStatusCode().value());
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals("Code should only be valid for one call", HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, "invalidClientId", CLIENT_SECRET, code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, "wrongsecret", code, REDIRECT_URI, null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
        
        try {
            token(dwServer, GRANT_AUTHORIZATION_CODE, CLIENT_ID, CLIENT_SECRET, code, "https://different_redirect", null);
        } catch (HttpStatusCodeException e) {
            Assert.assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
    
    private ResponseEntity<String> authorize(DatawaveUser user, String response_type, String client_id, String redirect_uri, String state) {
        ProxiedUserDetails authUser = new ProxiedUserDetails(Collections.singleton(user), user.getCreationTime());
        MultiValueMap<String,String> queryParams = new LinkedMultiValueMap<>();
        if (response_type != null) {
            queryParams.put("response_type", Collections.singletonList(response_type));
        }
        if (client_id != null) {
            queryParams.put("client_id", Collections.singletonList(client_id));
        }
        if (redirect_uri != null) {
            queryParams.put("redirect_uri", Collections.singletonList(redirect_uri));
        }
        if (state != null) {
            queryParams.put("state", Collections.singletonList(state));
        }
        UriComponents authorizeUri = UriComponentsBuilder.newInstance().scheme("https").host("localhost").port(webServicePort)
                        .path("/authorization/v2/oauth/authorize").queryParams(queryParams).build();
        return jwtRestTemplate.exchange(authUser, HttpMethod.GET, authorizeUri, String.class);
    }
    
    private ResponseEntity<OAuthTokenResponse> token(DatawaveUser user, String grant_type, String client_id, String client_secret, String code,
                    String redirect_uri, String refresh_token) {
        ProxiedUserDetails authUser = new ProxiedUserDetails(Collections.singleton(user), user.getCreationTime());
        MultiValueMap<String,String> queryParams = new LinkedMultiValueMap<>();
        if (grant_type != null) {
            queryParams.put("grant_type", Collections.singletonList(grant_type));
        }
        if (client_id != null) {
            queryParams.put("client_id", Collections.singletonList(client_id));
        }
        if (client_secret != null) {
            queryParams.put("client_secret", Collections.singletonList(client_secret));
        }
        if (redirect_uri != null) {
            queryParams.put("redirect_uri", Collections.singletonList(redirect_uri));
        }
        if (code != null) {
            queryParams.put("code", Collections.singletonList(code));
        }
        if (refresh_token != null) {
            queryParams.put("refresh_token", Collections.singletonList(refresh_token));
        }
        UriComponents tokenUri = UriComponentsBuilder.newInstance().scheme("https").host("localhost").port(webServicePort).path("/authorization/v2/oauth/token")
                        .queryParams(queryParams).build();
        
        return jwtRestTemplate.exchange(authUser, HttpMethod.POST, tokenUri, OAuthTokenResponse.class);
    }
    
    private ResponseEntity<OAuthUserInfo> user(String token, String claim) {
        Collection<DatawaveUser> dwUsers = jwtTokenHandler.createUsersFromToken(token, claim);
        ProxiedUserDetails authUser = new ProxiedUserDetails(dwUsers, dwUsers.stream().findFirst().get().getCreationTime());
        UriComponents userUri = UriComponentsBuilder.newInstance().scheme("https").host("localhost").port(webServicePort).path("/authorization/v2/oauth/user")
                        .build();
        return jwtRestTemplate.exchange(authUser, HttpMethod.GET, userUri, OAuthUserInfo.class);
    }
    
    private ResponseEntity<OAuthUserInfo[]> users(String token, String claim) {
        Collection<DatawaveUser> dwUsers = jwtTokenHandler.createUsersFromToken(token, claim);
        ProxiedUserDetails authUser = new ProxiedUserDetails(dwUsers, dwUsers.stream().findFirst().get().getCreationTime());
        UriComponents userUri = UriComponentsBuilder.newInstance().scheme("https").host("localhost").port(webServicePort).path("/authorization/v2/oauth/users")
                        .build();
        return jwtRestTemplate.exchange(authUser, HttpMethod.GET, userUri, OAuthUserInfo[].class);
    }
    
    public static Map<String,List<String>> splitQuery(URL url) throws UnsupportedEncodingException {
        final Map<String,List<String>> query_pairs = new LinkedHashMap<>();
        final String[] pairs = url.getQuery().split("&");
        for (String pair : pairs) {
            final int idx = pair.indexOf("=");
            final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
            if (!query_pairs.containsKey(key)) {
                query_pairs.put(key, new LinkedList<>());
            }
            final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
            query_pairs.get(key).add(value);
        }
        return query_pairs;
    }
    
    @ImportAutoConfiguration({RefreshAutoConfiguration.class})
    @AutoConfigureCache(cacheProvider = CacheType.HAZELCAST)
    @ComponentScan(basePackages = "datawave.microservice")
    @Profile("OAuthServiceTest")
    @Configuration
    public static class AuthorizationServiceTestConfiguration {
        @Bean
        public CachedDatawaveUserService oauthCachedDatawaveUserService() {
            return new TestUserService(OAuthOperationsV2Test.userMap);
        }
        
        @Bean
        public HazelcastInstance testHazelcastInstance() {
            Config config = new Config();
            config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
            return Hazelcast.newHazelcastInstance(config);
        }
    }
    
    @EnableCaching
    @CacheConfig(cacheNames = "datawaveUsers-IT")
    private static class TestUserService implements CachedDatawaveUserService {
        
        private Map<SubjectIssuerDNPair,DatawaveUser> userMap;
        
        public TestUserService(Map<SubjectIssuerDNPair,DatawaveUser> userMap) {
            this.userMap = userMap;
        }
        
        @Override
        public Collection<DatawaveUser> lookup(Collection<SubjectIssuerDNPair> dns) throws AuthorizationException {
            return dns.stream().map(dn -> this.userMap.get(dn)).collect(toList());
        }
        
        @Override
        public Collection<DatawaveUser> reload(Collection<SubjectIssuerDNPair> dns) throws AuthorizationException {
            return null;
        }
        
        @Override
        public DatawaveUser list(String name) {
            return null;
        }
        
        @Override
        public Collection<? extends DatawaveUserInfo> listAll() {
            return null;
        }
        
        @Override
        public Collection<? extends DatawaveUserInfo> listMatching(String substring) {
            return null;
        }
        
        @Override
        public String evict(String name) {
            return null;
        }
        
        @Override
        public String evictMatching(String substring) {
            return null;
        }
        
        @Override
        public String evictAll() {
            return null;
        }
    }
    
    /*
     * Only used for the OAuth tests so that we can ignore redirect responses and check the response values at each step of the OAuth process
     */
    public class OAuthRestTemplateCustomizer implements RestTemplateCustomizer {
        
        private final SSLContext sslContext;
        private final int maxConnectionsTotal;
        private final int maxConnectionsPerRoute;
        
        public OAuthRestTemplateCustomizer(SSLContext sslContext, RestClientProperties restClientProperties) {
            this.sslContext = sslContext;
            this.maxConnectionsTotal = restClientProperties.getMaxConnectionsTotal();
            this.maxConnectionsPerRoute = restClientProperties.getMaxConnectionsPerRoute();
        }
        
        @Override
        public void customize(RestTemplate restTemplate) {
            restTemplate.setRequestFactory(clientHttpRequestFactory());
        }
        
        protected ClientHttpRequestFactory clientHttpRequestFactory() {
            HttpClient httpClient = customizeHttpClient(HttpClients.custom(), sslContext).build();
            return new HttpComponentsClientHttpRequestFactory(httpClient);
        }
        
        protected HttpClientBuilder customizeHttpClient(HttpClientBuilder httpClientBuilder, SSLContext sslContext) {
            if (sslContext != null) {
                httpClientBuilder.setSSLContext(sslContext);
            }
            httpClientBuilder.setMaxConnTotal(maxConnectionsTotal);
            httpClientBuilder.setMaxConnPerRoute(maxConnectionsPerRoute);
            httpClientBuilder.disableRedirectHandling();
            // TODO: We're allowing all hosts, since the cert presented by the service we're calling likely won't match its hostname (e.g., a docker host name)
            // Instead, we could list the expected cert as a property (or use our server cert), and verify that the presented name matches.
            return httpClientBuilder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
        }
    }
    
    private static class NoOpResponseErrorHandler extends DefaultResponseErrorHandler {
        
        @Override
        public void handleError(ClientHttpResponse response) throws IOException {}
        
    }
}
