package datawave.microservice.authorization;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.microservice.cached.CacheInspector;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.JWTTokenHandler;
import datawave.security.authorization.SubjectIssuerDNPair;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheType;
import org.springframework.boot.test.autoconfigure.core.AutoConfigureCache;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.cache.CacheManager;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;

import static datawave.security.authorization.DatawaveUser.UserType.USER;
import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"AuthorizationServiceV1HttpTest", "http"})
public class AuthorizeHttpTest {
    
    private static final SubjectIssuerDNPair ALLOWED_CALLER = SubjectIssuerDNPair.of("cn=test.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private static final SubjectIssuerDNPair NOT_ALOWED_CALLER = SubjectIssuerDNPair.of(
                    "cn=notallowedcaller.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us", "cn=testcorp ca, ou=security, o=testcorp, c=us");
    
    @LocalServerPort
    private int webServicePort;
    
    @Autowired
    private RestTemplateBuilder restTemplateBuilder;
    
    @Autowired
    private CacheManager cacheManager;
    
    @Autowired
    private JWTTokenHandler jwtTokenHandler;
    
    private AuthorizationTestUtils testUtils;
    
    private ProxiedUserDetails allowedCaller;
    private ProxiedUserDetails notAllowedCaller;
    private RestTemplate restTemplate;
    
    @Before
    public void setup() {
        cacheManager.getCacheNames().forEach(name -> cacheManager.getCache(name).clear());
        restTemplate = restTemplateBuilder.build(RestTemplate.class);
        testUtils = new AuthorizationTestUtils(jwtTokenHandler, restTemplate, "http", webServicePort);
        
        DatawaveUser allowedDWUser = new DatawaveUser(ALLOWED_CALLER, USER, null, null, null, null, System.currentTimeMillis());
        allowedCaller = new ProxiedUserDetails(Collections.singleton(allowedDWUser), allowedDWUser.getCreationTime());
        
        DatawaveUser notAllowedDWUser = new DatawaveUser(NOT_ALOWED_CALLER, USER, null, null, null, null, System.currentTimeMillis());
        notAllowedCaller = new ProxiedUserDetails(Collections.singleton(notAllowedDWUser), notAllowedDWUser.getCreationTime());
    }
    
    @Test
    public void testAuthorizeNotAllowedCallerTrustedHeader() throws Exception {
        // Use trusted header to authenticate to ProxiedEntityX509Filter
        testUtils.testAuthorizeMethodFailure(notAllowedCaller, "/authorization/v1/authorize", true, false);
        testUtils.testAuthorizeMethodFailure(notAllowedCaller, "/authorization/v2/authorize", true, false);
    }
    
    @Test
    public void testAuthorizeJWTTrustedHeader() throws Exception {
        // Use JWT to authenticate to JWTAuthenticationFilter
        // Since user is already authenticated, ProxiedEntityX509Filter does not
        // authenticate and trustedHeaders are ignored
        testUtils.testAuthorizeMethodSuccess(allowedCaller, "/authorization/v1/authorize", true, true);
        testUtils.testAuthorizeMethodSuccess(allowedCaller, "/authorization/v2/authorize", true, true);
        
        // Use JWT to authenticate to JWTAuthenticationFilter
        // Since user is already authenticated, ProxiedEntityX509Filter does not
        // authenticate and trustedHeaders are ignored
        // allowedCaller is not enforced when accessing using JWT
        testUtils.testAuthorizeMethodSuccess(notAllowedCaller, "/authorization/v1/authorize", true, true);
        testUtils.testAuthorizeMethodSuccess(notAllowedCaller, "/authorization/v2/authorize", true, true);
    }
    
    @Test
    public void testAuthorizeJWT() throws Exception {
        // Use JWT to authenticate to JWTAuthenticationFilter
        testUtils.testAuthorizeMethodSuccess(allowedCaller, "/authorization/v1/authorize", false, true);
        testUtils.testAuthorizeMethodSuccess(allowedCaller, "/authorization/v2/authorize", false, true);
        
        // Use JWT to authenticate to JWTAuthenticationFilter
        // allowedCaller is not enforced when accessing using JWT
        testUtils.testAuthorizeMethodSuccess(notAllowedCaller, "/authorization/v1/authorize", false, true);
        testUtils.testAuthorizeMethodSuccess(notAllowedCaller, "/authorization/v2/authorize", false, true);
    }
    
    @Test
    public void testAuthorizeAllowedCallerTrustedHeader() throws Exception {
        // Use trusted header to authenticate to ProxiedEntityX509Filter
        testUtils.testAuthorizeMethodSuccess(allowedCaller, "/authorization/v1/authorize", true, false);
        testUtils.testAuthorizeMethodSuccess(allowedCaller, "/authorization/v2/authorize", true, false);
    }
    
    @Test
    public void testAuthorizeNoPrincipalChangedCheck() throws Exception {
        // Checking for setCheckForPrincipalChanges(false) in ProxiedEntityX509Filter()
        // If user is authenticated using JWT, then ProxiedEntityX509Filter should not be used
        // If setCheckForPrincipalChanges(true) and we checked for a changed principal, then the trusted header
        // user would be authenticated and notAllowedCaller would be checked against the allowedCallers list
        // allowedCaller is not enforced when accessing using JWT
        UriComponents uri = UriComponentsBuilder.newInstance().scheme("http").host("localhost").port(webServicePort).path("/authorization/v1/authorize")
                        .build();
        RequestEntity requestEntity = testUtils.createRequestEntity(notAllowedCaller, allowedCaller, HttpMethod.GET, uri);
        ResponseEntity<String> responseEntity = restTemplate.exchange(requestEntity, String.class);
        assertEquals("Authorized request to " + uri + " did not return a 200.", HttpStatus.OK, responseEntity.getStatusCode());
    }
    
    @ImportAutoConfiguration({RefreshAutoConfiguration.class})
    @AutoConfigureCache(cacheProvider = CacheType.HAZELCAST)
    @ComponentScan(basePackages = "datawave.microservice")
    @Profile("AuthorizationServiceV1HttpTest")
    @Configuration
    public static class AuthorizationServiceTestConfiguration {
        @Bean
        public CachedDatawaveUserService cachedDatawaveUserService(CacheManager cacheManager, CacheInspector cacheInspector) {
            return new AuthorizationTestUserService(Collections.emptyMap(), true);
        }
        
        @Bean
        public HazelcastInstance testHazelcastInstance() {
            Config config = new Config();
            config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
            return Hazelcast.newHazelcastInstance(config);
        }
    }
}
