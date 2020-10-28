package example.micronaut;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.validator.JwtValidator;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

public class AbstractCustomTokenValidator implements TokenValidator  {

    protected final JwtAuthenticationFactory jwtAuthenticationFactory;
    private final JwtValidator validator;

    /**
     * @param validator Validates the JWT
     * @param jwtAuthenticationFactory The authentication factory
     */
    public AbstractCustomTokenValidator(JwtValidator validator,
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
