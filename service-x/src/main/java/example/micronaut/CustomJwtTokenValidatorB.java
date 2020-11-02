package example.micronaut;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.validator.JwtValidator;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collection;

@Requires(property = CustomTokenAuthenticationFetcher.PREFIX + ".enabled", value = "true")
@Named(CustomJwtTokenValidatorConstants.JWT_TOKEN_VALIDATOR_B)
@Singleton
public class CustomJwtTokenValidatorB extends AbstractCustomTokenValidator  {

    @Inject
    public CustomJwtTokenValidatorB(@Named(CustomJwtTokenValidatorConstants.JWKS_GENERATOR_B) SignatureConfiguration jwksSignatureConfiguration,
                                    Collection<EncryptionConfiguration> encryptionConfigurations,
                                    Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                                    JwtAuthenticationFactory jwtAuthenticationFactory) {
        super(JwtValidator.builder()
                .withSignatures(jwksSignatureConfiguration)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(genericJwtClaimsValidators)
                .build(), jwtAuthenticationFactory);
    }

}
