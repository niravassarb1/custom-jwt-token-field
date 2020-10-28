package example.micronaut;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import io.micronaut.security.token.jwt.validator.JwtValidator;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collection;

@Replaces(JwtTokenValidator.class)
@Named("jwt-token-validator-a")
@Singleton
public class CustomJwtTokenValidatorA implements TokenValidator {

    protected final JwtAuthenticationFactory jwtAuthenticationFactory;
    private final JwtValidator validator;

    @Inject
    public CustomJwtTokenValidatorA(@Named("jwks-generator-a") SignatureConfiguration jwksSignatureConfiguration,
                             Collection<EncryptionConfiguration> encryptionConfigurations,
                             Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                             JwtAuthenticationFactory jwtAuthenticationFactory) {
        this(JwtValidator.builder()
                .withSignatures(jwksSignatureConfiguration)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(genericJwtClaimsValidators)
                .build(), jwtAuthenticationFactory);
    }

    /**
     * @param validator Validates the JWT
     * @param jwtAuthenticationFactory The authentication factory
     */
    public CustomJwtTokenValidatorA(JwtValidator validator,
                             JwtAuthenticationFactory jwtAuthenticationFactory) {
        this.validator = validator;
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
    }

    /***
     * @param token The token string.
     * @return Publishes {@link Authentication} based on the JWT or empty if the validation fails.
     */
    @Override
    @Deprecated
    public Publisher<Authentication> validateToken(String token) {
        return validator.validate(token)
                .flatMap(jwtAuthenticationFactory::createAuthentication)
                .map(Flowable::just)
                .orElse(Flowable.empty());
    }

}
