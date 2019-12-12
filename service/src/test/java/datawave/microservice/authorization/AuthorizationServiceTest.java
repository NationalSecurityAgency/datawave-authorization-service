package datawave.microservice.authorization;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import datawave.microservice.authorization.jwt.JWTRestTemplate;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserInfo;
import datawave.security.authorization.SubjectIssuerDNPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheType;
import org.springframework.boot.test.autoconfigure.core.AutoConfigureCache;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import static datawave.security.authorization.DatawaveUser.UserType.USER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

//@Category(IntegrationTest.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthorizationServiceTest {
    private static final SubjectIssuerDNPair DN = SubjectIssuerDNPair.of("userDn", "issuerDn");
    
    @LocalServerPort
    private int webServicePort;
    
    @Autowired
    private RestTemplateBuilder restTemplateBuilder;
    
    @Autowired
    private CacheManager cacheManager;
    
    private JWTRestTemplate jwtRestTemplate;
    
    @BeforeEach
    public void setup() {
        cacheManager.getCacheNames().forEach(name -> cacheManager.getCache(name).clear());
        jwtRestTemplate = restTemplateBuilder.build(JWTRestTemplate.class);
    }
    
    @Test
    public void testAdminMethodSecurity() throws Exception {
        DatawaveUser unuathDWUser = new DatawaveUser(DN, USER, null, null, null, System.currentTimeMillis());
        ProxiedUserDetails unuathUser = new ProxiedUserDetails(Collections.singleton(unuathDWUser), unuathDWUser.getCreationTime());
        
        testAdminMethodFailure(unuathUser, "/authorization/v1/admin/evictAll", null);
        testAdminMethodFailure(unuathUser, "/authorization/v1/admin/evictUser", "username=ignored");
        testAdminMethodFailure(unuathUser, "/authorization/v1/admin/evictUsersMatching", "substring=ignored");
        testAdminMethodFailure(unuathUser, "/authorization/v1/admin/listUsers", null);
        testAdminMethodFailure(unuathUser, "/authorization/v1/admin/listUser", "username=ignored");
        testAdminMethodFailure(unuathUser, "/authorization/v1/admin/listUsersMatching", "substring=ignore");
        
        Collection<String> roles = Collections.singleton("Administrator");
        DatawaveUser authDWUser = new DatawaveUser(DN, USER, null, roles, null, System.currentTimeMillis());
        ProxiedUserDetails authUser = new ProxiedUserDetails(Collections.singleton(authDWUser), authDWUser.getCreationTime());
        
        testAdminMethodSuccess(authUser, "/authorization/v1/admin/evictAll", null);
        testAdminMethodSuccess(authUser, "/authorization/v1/admin/evictUser", "username=ignored");
        testAdminMethodSuccess(authUser, "/authorization/v1/admin/evictUsersMatching", "substring=ignored");
        testAdminMethodSuccess(authUser, "/authorization/v1/admin/listUsers", null);
        testAdminMethodSuccess(authUser, "/authorization/v1/admin/listUser", "username=ignored");
        testAdminMethodSuccess(authUser, "/authorization/v1/admin/listUsersMatching", "substring=ignore");
    }
    
    private void testAdminMethodFailure(ProxiedUserDetails unauthUser, String path, String query) {
        UriComponents uri = UriComponentsBuilder.newInstance().scheme("https").host("localhost").port(webServicePort).path(path).query(query).build();
        try {
            jwtRestTemplate.exchange(unauthUser, HttpMethod.GET, uri, String.class);
            fail("Non-admin request to " + uri + " shouldn't have been allowed.");
        } catch (HttpClientErrorException e) {
            assertEquals(403, e.getRawStatusCode());
            assertEquals("Forbidden", e.getStatusText());
        }
    }
    
    private void testAdminMethodSuccess(ProxiedUserDetails authUser, String path, String query) {
        UriComponents uri = UriComponentsBuilder.newInstance().scheme("https").host("localhost").port(webServicePort).path(path).query(query).build();
        ResponseEntity<String> entity = jwtRestTemplate.exchange(authUser, HttpMethod.GET, uri, String.class);
        assertEquals(HttpStatus.OK, entity.getStatusCode(), "Authorizaed admin request to " + uri + " did not return a 200.");
    }
    
    @ImportAutoConfiguration({RefreshAutoConfiguration.class})
    @AutoConfigureCache(cacheProvider = CacheType.HAZELCAST)
    @ComponentScan(basePackages = "datawave.microservice")
    @Configuration
    public static class AuthorizationServiceTestConfiguration {
        @Bean
        public CachedDatawaveUserService cachedDatawaveUserService() {
            return new TestUserService();
        }
        
        @Bean
        public HazelcastInstance testHazelcastInstance() {
            Config config = new Config();
            config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
            config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
            return Hazelcast.newHazelcastInstance(config);
        }
    }
    
    @EnableCaching
    @CacheConfig(cacheNames = "datawaveUsers-IT")
    private static class TestUserService implements CachedDatawaveUserService {
        @Override
        public Collection<DatawaveUser> lookup(Collection<SubjectIssuerDNPair> dns) {
            return dns.stream().map(dn -> new DatawaveUser(dn, USER, null, null, null, -1L)).collect(Collectors.toList());
        }
        
        @Override
        public Collection<DatawaveUser> reload(Collection<SubjectIssuerDNPair> dns) {
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
}
