package datawave.microservice.authorization;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import datawave.microservice.authorization.datawave.microservice.authorization.preauth.AuthorizationProxiedEntityPreauthPrincipal;
import datawave.microservice.authorization.user.ProxiedUserDetails;
import datawave.microservice.authorization.userdetails.ProxiedEntityUserDetailsService;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.SubjectIssuerDNPair;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheType;
import org.springframework.boot.test.autoconfigure.core.AutoConfigureCache;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"ProxiedEntityUserDetailsServiceTest"})
public class ProxiedEntityUserDetailsServiceTest {
    
    private static final SubjectIssuerDNPair CALLER = SubjectIssuerDNPair.of("cn=test.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private static final SubjectIssuerDNPair USER_1 = SubjectIssuerDNPair.of("cn=user1.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private static final SubjectIssuerDNPair USER_2 = SubjectIssuerDNPair.of("cn=user2.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    private static final SubjectIssuerDNPair USER_3 = SubjectIssuerDNPair.of("cn=user3.testcorp.com, ou=microservices, ou=development, o=testcorp, c=us",
                    "cn=testcorp ca, ou=security, o=testcorp, c=us");
    
    @Autowired
    private ProxiedEntityUserDetailsService userDetailsService;
    
    @Before
    public void setup() {
        
    }
    
    @Test
    public void withProxiedUsers() {
        List<SubjectIssuerDNPair> proxiedEntities = new ArrayList<>();
        proxiedEntities.add(USER_1);
        proxiedEntities.add(USER_2);
        proxiedEntities.add(USER_3);
        AuthorizationProxiedEntityPreauthPrincipal principal = new AuthorizationProxiedEntityPreauthPrincipal(CALLER, proxiedEntities, null);
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, null);
        ProxiedUserDetails proxiedUserDetails = (ProxiedUserDetails) userDetailsService.loadUserDetails(token);
        // ProxiedEntityUserDetailsService should return a ProxiedUserDetails with the caller and all proxied users
        Assert.assertEquals(4, proxiedUserDetails.getProxiedUsers().size());
        Assert.assertEquals(CALLER, proxiedUserDetails.getProxiedUsers().stream().findFirst().get().getDn());
        Assert.assertEquals(USER_1, proxiedUserDetails.getProxiedUsers().stream().skip(1).findFirst().get().getDn());
        Assert.assertEquals(USER_2, proxiedUserDetails.getProxiedUsers().stream().skip(2).findFirst().get().getDn());
        Assert.assertEquals(USER_3, proxiedUserDetails.getProxiedUsers().stream().skip(3).findFirst().get().getDn());
    }
    
    @Test
    public void withCallerOnly() {
        List<SubjectIssuerDNPair> proxiedEntities = new ArrayList<>();
        AuthorizationProxiedEntityPreauthPrincipal principal = new AuthorizationProxiedEntityPreauthPrincipal(CALLER, proxiedEntities, null);
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, null);
        ProxiedUserDetails proxiedUserDetails = (ProxiedUserDetails) userDetailsService.loadUserDetails(token);
        // ProxiedEntityUserDetailsService should return a ProxiedUserDetails with only the caller
        Assert.assertEquals(1, proxiedUserDetails.getProxiedUsers().size());
        Assert.assertEquals(CALLER, proxiedUserDetails.getProxiedUsers().stream().findFirst().get().getDn());
    }
    
    @Test
    public void withCallerInProxiedUsers() {
        List<SubjectIssuerDNPair> proxiedEntities = new ArrayList<>();
        proxiedEntities.add(USER_1);
        proxiedEntities.add(CALLER);
        AuthorizationProxiedEntityPreauthPrincipal principal = new AuthorizationProxiedEntityPreauthPrincipal(CALLER, proxiedEntities, null);
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, null);
        ProxiedUserDetails proxiedUserDetails = (ProxiedUserDetails) userDetailsService.loadUserDetails(token);
        // ProxiedEntityUserDetailsService should return a ProxiedUserDetails with the caller and all proxied users
        Assert.assertEquals(3, proxiedUserDetails.getProxiedUsers().size());
        Assert.assertEquals(CALLER, proxiedUserDetails.getProxiedUsers().stream().findFirst().get().getDn());
        Assert.assertEquals(USER_1, proxiedUserDetails.getProxiedUsers().stream().skip(1).findFirst().get().getDn());
        Assert.assertEquals(CALLER, proxiedUserDetails.getProxiedUsers().stream().skip(2).findFirst().get().getDn());
    }
    
    @ImportAutoConfiguration({RefreshAutoConfiguration.class})
    @AutoConfigureCache(cacheProvider = CacheType.HAZELCAST)
    @ComponentScan(basePackages = "datawave.microservice")
    @Profile("ProxiedEntityUserDetailsServiceTest")
    @Configuration
    public static class ProxiedEntityUserDetailsServiceTestConfiguration {
        @Bean
        public CachedDatawaveUserService cachedDatawaveUserService() {
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
