package example.micronaut;

import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.validator.JwtValidator;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collection;

@Named("jwt-token-validator-b")
@Singleton
public class CustomJwtTokenValidatorB extends AbstractCustomTokenValidator  {

    @Inject
    public CustomJwtTokenValidatorB(@Named("jwks-generator-b") SignatureConfiguration jwksSignatureConfiguration,
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
