package example.micronaut;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.event.TokenValidatedEvent;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.token.TokenAuthenticationFetcher;
import io.micronaut.security.token.reader.TokenResolver;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.web.router.RouteMatch;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.List;
import java.util.Optional;

import static io.micronaut.security.filters.SecurityFilter.TOKEN;

@Requires(property = CustomTokenAuthenticationFetcher.PREFIX + ".enabled", value = "true")
@Replaces(TokenAuthenticationFetcher.class)
@Singleton
public class CustomTokenAuthenticationFetcher implements AuthenticationFetcher {

    public static final String PREFIX = "b1x.security.jwt-token-per-endpoint";

    /**
     * The order of the fetcher.
     */
    public static final Integer ORDER = 0;

    protected final TokenValidator jwtTokenValidatorA;
    protected final TokenValidator jwtTokenValidatorB;
    protected final ApplicationEventPublisher eventPublisher;
    private final TokenResolver tokenResolver;
    private final JwtTokenPerEndpointAnnotationRule jwtTokenPerEndpointAnnotationRule;

    @Inject
    public CustomTokenAuthenticationFetcher(@Named("jwt-token-validator-a") TokenValidator jwtTokenValidatorA,
                                            @Named("jwt-token-validator-b") TokenValidator jwtTokenValidatorB,
                                            TokenResolver tokenResolver,
                                            ApplicationEventPublisher eventPublisher,
                                            JwtTokenPerEndpointAnnotationRule jwtTokenPerEndpointAnnotationRule) {

        this.eventPublisher = eventPublisher;
        this.tokenResolver = tokenResolver;
        this.jwtTokenValidatorA = jwtTokenValidatorA;
        this.jwtTokenValidatorB = jwtTokenValidatorB;
        this.jwtTokenPerEndpointAnnotationRule = jwtTokenPerEndpointAnnotationRule;
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {

        Optional<String> token = tokenResolver.resolveToken(request);

        if (!token.isPresent()) {
            return Flowable.empty();
        }

        String tokenValue = token.get();

        // URI logic goes here
        RouteMatch<?> routeMatch = request.getAttribute(HttpAttributes.ROUTE_MATCH, RouteMatch.class).orElse(null);
        String jwtTokenPerEndpointAnnotationValue = jwtTokenPerEndpointAnnotationRule.getJwksSignatureNames((routeMatch));
        if (request.getPath().equals("/endpoint-a")) {
            return validateTokenAndReturnAuthentication(tokenValue, request, jwtTokenValidatorA);
        } else if (request.getPath().equals("/endpoint-b")){
            return validateTokenAndReturnAuthentication(tokenValue, request, jwtTokenValidatorB);
        } else {
            return Flowable.empty();
        }
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    private Publisher<Authentication> validateTokenAndReturnAuthentication(String tokenValue, HttpRequest<?> request, TokenValidator customTokenValidator) {
        return Flowable.just(customTokenValidator)
                    .flatMap(tokenValidator -> tokenValidator.validateToken(tokenValue, request))
                    .firstElement()
                    .map(authentication -> {
                        request.setAttribute(TOKEN, tokenValue);
                        eventPublisher.publishEvent(new TokenValidatedEvent(tokenValue));
                        return authentication;
                    }).toFlowable();
    }
}