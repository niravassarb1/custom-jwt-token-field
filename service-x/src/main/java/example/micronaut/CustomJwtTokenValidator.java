package example.micronaut;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.signature.ec.ECSignature;
import io.micronaut.security.token.jwt.signature.ec.ECSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import io.micronaut.security.token.jwt.validator.JwtValidator;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;


/******** NOT USED*****************/
//@Replaces(JwtTokenValidator.class)
//@Context
public class CustomJwtTokenValidator /*implements TokenValidator*/ {
    private static final Logger LOG = LoggerFactory.getLogger(CustomJwtTokenValidator.class);

    protected final JwtAuthenticationFactory jwtAuthenticationFactory;
    protected final JwtValidator defaultValidator;

    protected final Collection<SignatureConfiguration> signatureConfigurations;
    protected final Collection<EncryptionConfiguration> encryptionConfigurations;
    protected final Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators;

    Map<String, List<SignatureConfiguration>> signatureMap;

    //@Inject
    public CustomJwtTokenValidator(Collection<SignatureConfiguration> signatureConfigurations,
                                   Collection<EncryptionConfiguration> encryptionConfigurations,
                                   Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                                   JwtAuthenticationFactory jwtAuthenticationFactory) {

        Map<String, List<SignatureConfiguration>> map = new HashMap<>();
        for (SignatureConfiguration signatureConfiguration : signatureConfigurations) {
            if (signatureConfiguration instanceof JwksSignature) {
                JwksSignature jwks = (JwksSignature) signatureConfiguration;

                //FIXME: trying to fix lazy initialisation of remote jwks data.
                signatureConfiguration.supportedAlgorithmsMessage();

                for (JWK jwk: jwks.getJwkSet().getKeys()) {
                    if (jwks.getKeyType().equals(KeyType.EC)) {
                        map.computeIfPresent(jwk.getKeyID(), (s, list) -> {
                            list.add(new ECSignature(new ECSignatureConfiguration() {
                                @Override
                                public ECPublicKey getPublicKey() {
                                    try {
                                        return jwk.toECKey().toECPublicKey();
                                    } catch (JOSEException e) {
                                        e.printStackTrace();
                                        return null;
                                    }
                                }
                                @Override
                                public JWSAlgorithm getJwsAlgorithm() {
                                    return JWSAlgorithm.parse(jwk.getAlgorithm().getName());
                                }
                            }));
                            return list;
                        });
                        map.computeIfAbsent(jwk.getKeyID(), s -> new ArrayList<>(){{
                            add(new ECSignature(new ECSignatureConfiguration() {
                                @Override
                                public ECPublicKey getPublicKey() {
                                    try {
                                        return jwk.toECKey().toECPublicKey();
                                    } catch (JOSEException e) {
                                        e.printStackTrace();
                                        return null;
                                    }
                                }
                                @Override
                                public JWSAlgorithm getJwsAlgorithm() {
                                    return JWSAlgorithm.parse(jwk.getAlgorithm().getName());
                                }
                            }));
                        }});
                    }
                }
            }
        }
        this.signatureMap = map;
        this.signatureConfigurations = signatureConfigurations;
        this.encryptionConfigurations = encryptionConfigurations;
        this.genericJwtClaimsValidators = genericJwtClaimsValidators;

        this.defaultValidator = JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(genericJwtClaimsValidators)
                .build();
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
    }

    public Publisher<Authentication> validateToken(String token) {

        //investigate which calls would come via this method without the request context. In this case, not sure
        //what can be done in terms of choosing a validator.

        return defaultValidator.validate(token)
                .flatMap(jwtAuthenticationFactory::createAuthentication)
                .map(Flowable::just)
                .orElse(Flowable.empty());
    }
    
    public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {

        //based on mapping/annotation decide which validator to use between default `validator`
        //and kid specific validator from validatorMap.
        List<String> identifiers = new ArrayList<>();

        List<SignatureConfiguration> matchingSignatures = signatureMap.entrySet().stream()
                .filter(entry -> identifiers.contains(entry.getKey()))
                .flatMap(list -> list.getValue().stream())
                .collect(Collectors.toList());

        if (!matchingSignatures.isEmpty()) {
            LOG.info("Using custom JwtValidator with signatures={}", matchingSignatures);
            JwtValidator customValidator = JwtValidator.builder()
                    .withSignatures(matchingSignatures)
                    .withEncryptions(encryptionConfigurations)
                    .withClaimValidators(genericJwtClaimsValidators)
                    .build();

            return customValidator.validate(token, request)
                    .flatMap(jwtAuthenticationFactory::createAuthentication)
                    .map(Flowable::just)
                    .orElse(Flowable.empty());
        }

        LOG.info("Using default JwtValidator with all signatures={}", signatureConfigurations);
        return defaultValidator.validate(token, request)
                .flatMap(jwtAuthenticationFactory::createAuthentication)
                .map(Flowable::just)
                .orElse(Flowable.empty());
    }
}
