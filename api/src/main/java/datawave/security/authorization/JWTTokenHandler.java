package datawave.security.authorization;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.impl.lang.LegacyServices;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;

/**
 * Converts between a String encoded JSON Web Token and a collection of {@link DatawaveUser}s.
 */
public class JWTTokenHandler {
    public enum TtlMode {
        RELATIVE_TO_CURRENT_TIME, RELATIVE_TO_CREATION_TIME
    }
    
    public static final String PRINCIPALS_CLAIM = "principals";
    public static final String REFRESH_TOKEN_CLAIM = "refresh";
    
    private final Logger logger = LoggerFactory.getLogger(getClass());
    
    private final String issuer;
    private final Key signingKey;
    private final Key signatureCheckKey;
    private final TtlMode ttlMode;
    private final long jwtTtl;
    private final ObjectMapper objectMapper;
    
    /**
     * Creates a new JWTTokenHandler.
     *
     * @param cert
     *            the certificate to use for retrieving the JWT issuer name to use when creating JWTs. {@code DATAWAVE} is used if null is passed. If a valid
     *            certificate is passed, then its public key will be used to verify the signature of signed JWTs.
     * @param signingKey
     *            the key to use for signing new JWTs (and checking the signature of existing JWTs if no cert is passed)
     * @param jwtTtl
     *            the length of time, relative to the oldest creation time of the {@link DatawaveUser} being converted to a JWT, for which a signed JWT will be
     *            valid
     * @param jwtTtlUnit
     *            the units of time for {@code jwtTtl}
     * @param objectMapper
     *            an {@link ObjectMapper} to use for converting a JWT back into a collection of {@link DatawaveUser}s
     */
    public JWTTokenHandler(Certificate cert, Key signingKey, long jwtTtl, TimeUnit jwtTtlUnit, ObjectMapper objectMapper) {
        this(cert, signingKey, jwtTtl, jwtTtlUnit, TtlMode.RELATIVE_TO_CREATION_TIME, objectMapper);
    }
    
    /**
     * Creates a new JWTTokenHandler.
     *
     * @param cert
     *            the certificate to use for retrieving the JWT issuer name to use when creating JWTs. {@code DATAWAVE} is used if null is passed. If a valid *
     *            certificate is passed, then its public key will be used to verify the signature of signed JWTs.
     * @param signingKey
     *            the key to use for signing new JWTs (and checking the signature of existing JWTs if no cert is passed)
     * @param jwtTtl
     *            the length of time (relative to either {@link DatawaveUser} creation time or now, based on the value of {@code ttlMode}) for which generated
     *            JWTs will be valid
     * @param jwtTtlUnit
     *            the units of time for {@code jwtTtl}
     * @param ttlMode
     *            the mode of calculation used to determine a signed JWT's expiration date. When the mode is {@code TtlMode.RELATIVE_TO_CURRENT_TIME}, the
     *            expiration time will be the current time plus {@code jwtTtl}. When the mode is {@code TtlMode.RELATIVE_TO_CREATION_TIME}, the expiration time
     *            will be the oldest creation time of the {@link DatawaveUser}s being converted to a JWT plus {@code jwtTtl}
     * @param objectMapper
     *            an {@link ObjectMapper} to use for converting a JWT back into a collection of {@link DatawaveUser}s
     */
    public JWTTokenHandler(Certificate cert, Key signingKey, long jwtTtl, TimeUnit jwtTtlUnit, TtlMode ttlMode, ObjectMapper objectMapper) {
        this.signingKey = signingKey;
        this.ttlMode = ttlMode;
        this.jwtTtl = jwtTtlUnit.toMillis(jwtTtl);
        this.objectMapper = objectMapper;
        if (cert instanceof X509Certificate) {
            issuer = ((X509Certificate) cert).getSubjectDN().getName();
            signatureCheckKey = cert.getPublicKey();
        } else {
            issuer = "DATAWAVE";
            signatureCheckKey = signingKey;
        }
    }
    
    public String createTokenFromUsers(String username, Collection<? extends DatawaveUser> users, String claimName, Date expirationDate) {
        logger.trace("Creating new JWT to expire at {} for users {}", expirationDate, users);
        // @formatter:off
        return new DefaultJwtBuilder()
                .serializeToJsonWith(new Serializer<Map<String,?>>() {
                    @Override
                    public byte[] serialize(Map<String,?> map) throws SerializationException {
                        try {
                            return objectMapper.writeValueAsBytes(map);
                        } catch (JsonProcessingException e) {
                            throw new SerializationException(e.getMessage(), e);
                        }
                    }
                })
                .setSubject(username)
                .setAudience("DATAWAVE")
                .setIssuer(issuer)
                .setExpiration(expirationDate)
                .claim(claimName, users)
                .signWith(signingKey, SignatureAlgorithm.RS512)
                .compressWith(CompressionCodecs.DEFLATE)
                .compact();
        // @formatter:on
    }
    
    public String createTokenFromUsers(String username, Collection<? extends DatawaveUser> users) {
        long minCreationTime = users.stream().map(DatawaveUser::getCreationTime).min(Long::compareTo).orElse(System.currentTimeMillis());
        if (ttlMode == TtlMode.RELATIVE_TO_CURRENT_TIME) {
            minCreationTime = System.currentTimeMillis();
        }
        Date expirationDate = new Date(minCreationTime + jwtTtl);
        return createTokenFromUsers(username, users, PRINCIPALS_CLAIM, expirationDate);
    }
    
    public Collection<DatawaveUser> createUsersFromToken(String token) {
        return createUsersFromToken(token, PRINCIPALS_CLAIM);
    }
    
    public Collection<DatawaveUser> createUsersFromToken(String token, String claimName) {
        logger.trace("Attempting to parse JWT {}", token);
        Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(signatureCheckKey).build().parseClaimsJws(token);
        Claims claims = claimsJws.getBody();
        logger.trace("Resulting claims: {}", claims);
        List<?> principalsClaim = claims.get(claimName, List.class);
        if (principalsClaim == null || principalsClaim.isEmpty()) {
            throw new IllegalArgumentException("JWT for " + claims.getSubject() + " does not contain any proxied principals.");
        }
        return principalsClaim.stream().map(obj -> objectMapper.convertValue(obj, DatawaveUser.class)).collect(Collectors.toList());
    }
}

/*
 * 
 * Finished going through all 28 submodules and replacing their deprecated calls as of now, I have 10 pr's up replacing different calls. All are passing, I'll
 * send you the list. There are 5 submodules that still have deprecated call relating to In memory accumulo and other interconnected stuff, That's what I'm
 * going to focus on next. - - core/in-memory-accumulo ***Replace test cases with mini-accumulo***, we'll try to get rid of actual reference to
 * in-memory-accumulo - - microservices/services/accumulo - - microservices/services/authorization - I have a comment about this one on the PR, I'm not sure if
 * anything will need to be updated on the Accumulo end or not. - - microservices/services/query-metrics - - microservices/starters/datawave
 * 
 */
