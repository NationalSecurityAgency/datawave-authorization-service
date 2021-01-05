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
import org.junit.BeforeClass;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import java.util.Collection;
import java.util.Collections;

import static datawave.security.authorization.DatawaveUser.UserType.USER;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"AuthorizationServiceV2Test"})
public class AuthorizationServiceV2Test {
    
    private static final SubjectIssuerDNPair ALLOWED_ADMIN_CALLER = SubjectIssuerDNPair
                    .of("cn=test.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us", "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private static final SubjectIssuerDNPair ALLOWED_NONADMIN_CALLER = SubjectIssuerDNPair
                    .of("cn=test2.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us", "cn=testcorp ca, ou=security, o=testcorp, c=us");
    
    @LocalServerPort
    private int webServicePort;
    
    @Autowired
    private RestTemplateBuilder restTemplateBuilder;
    
    @Autowired
    private CacheManager cacheManager;
    
    @Autowired
    private JWTTokenHandler jwtTokenHandler;
    
    private AuthorizationTestUtils testUtils;
    
    private static ProxiedUserDetails allowedAdminCaller;
    private static ProxiedUserDetails allowedNonAdminCaller;
    
    @BeforeClass
    public static void classSetup() {
        Collection<String> roles = Collections.singleton("Administrator");
        DatawaveUser allowedAdminDWUser = new DatawaveUser(ALLOWED_ADMIN_CALLER, USER, null, null, roles, null, System.currentTimeMillis());
        allowedAdminCaller = new ProxiedUserDetails(Collections.singleton(allowedAdminDWUser), allowedAdminDWUser.getCreationTime());
        
        DatawaveUser allowedNonAdminDWUser = new DatawaveUser(ALLOWED_NONADMIN_CALLER, USER, null, null, null, null, System.currentTimeMillis());
        allowedNonAdminCaller = new ProxiedUserDetails(Collections.singleton(allowedNonAdminDWUser), allowedNonAdminDWUser.getCreationTime());
    }
    
    @Before
    public void setup() {
        cacheManager.getCacheNames().forEach(name -> cacheManager.getCache(name).clear());
        RestTemplate restTemplate = restTemplateBuilder.build(RestTemplate.class);
        testUtils = new AuthorizationTestUtils(jwtTokenHandler, restTemplate, "https", webServicePort);
    }
    
    @Test
    public void testAdminMethodSecurity() throws Exception {
        
        // the call is being authenticated using a JWT of the provided user. The roles are encapsulated in the JWT
        testUtils.testAdminMethodFailure(allowedNonAdminCaller, "/authorization/v2/admin/evictUser", "username=ignored");
        testUtils.testAdminMethodFailure(allowedNonAdminCaller, "/authorization/v2/admin/evictUsersMatching", "substring=ignored");
        testUtils.testAdminMethodFailure(allowedNonAdminCaller, "/authorization/v2/admin/listUsers", null);
        testUtils.testAdminMethodFailure(allowedNonAdminCaller, "/authorization/v2/admin/listUser", "username=ignored");
        testUtils.testAdminMethodFailure(allowedNonAdminCaller, "/authorization/v2/admin/listUsersMatching", "substring=ignore");
        
        testUtils.testAdminMethodSuccess(allowedAdminCaller, "/authorization/v2/admin/evictAll", null);
        testUtils.testAdminMethodSuccess(allowedAdminCaller, "/authorization/v2/admin/evictUser", "username=ignored");
        testUtils.testAdminMethodSuccess(allowedAdminCaller, "/authorization/v2/admin/evictUsersMatching", "substring=ignored");
        testUtils.testAdminMethodSuccess(allowedAdminCaller, "/authorization/v2/admin/listUsers", null);
        testUtils.testAdminMethodSuccess(allowedAdminCaller, "/authorization/v2/admin/listUser", "username=ignored");
        testUtils.testAdminMethodSuccess(allowedAdminCaller, "/authorization/v2/admin/listUsersMatching", "substring=ignore");
    }
    
    @ImportAutoConfiguration({RefreshAutoConfiguration.class})
    @AutoConfigureCache(cacheProvider = CacheType.HAZELCAST)
    @ComponentScan(basePackages = "datawave.microservice")
    @Profile("AuthorizationServiceV2Test")
    @Configuration
    public static class AuthorizationServiceTestConfiguration {
        @Bean
        public CachedDatawaveUserService cachedDatawaveUserService(CacheManager cacheManager, CacheInspector cacheInspector) {
            return new AuthorizationTestUserService(Collections.EMPTY_MAP, true);
        }
        
        @Bean
        public HazelcastInstance testHazelcastInstance() {
            Config config = new Config();
            config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
            return Hazelcast.newHazelcastInstance(config);
        }
    }
}
