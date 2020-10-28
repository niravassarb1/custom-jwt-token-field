package example.micronaut;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.event.TokenValidatedEvent;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.token.TokenAuthenticationFetcher;
import io.micronaut.security.token.reader.TokenResolver;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

import static io.micronaut.security.filters.SecurityFilter.TOKEN;

@Replaces(TokenAuthenticationFetcher.class)
@Singleton
public class CustomTokenAuthenticationFetcher implements AuthenticationFetcher {

    /**
     * The order of the fetcher.
     */
    public static final Integer ORDER = 0;

    protected final TokenValidator jwtTokenValidatorA;
    protected final TokenValidator jwtTokenValidatorB;
    protected final ApplicationEventPublisher eventPublisher;
    private final TokenResolver tokenResolver;

    @Inject
    public CustomTokenAuthenticationFetcher(@Named("jwt-token-validator-a") TokenValidator jwtTokenValidatorA,
                                            @Named("jwt-token-validator-b") TokenValidator jwtTokenValidatorB,
                                      TokenResolver tokenResolver,
                                      ApplicationEventPublisher eventPublisher) {

        this.eventPublisher = eventPublisher;
        this.tokenResolver = tokenResolver;
        this.jwtTokenValidatorA = jwtTokenValidatorA;
        this.jwtTokenValidatorB = jwtTokenValidatorB;
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {

        Optional<String> token = tokenResolver.resolveToken(request);

        if (!token.isPresent()) {
            return Flowable.empty();
        }

        String tokenValue = token.get();

        Collection<TokenValidator> jwtTokenValidatorAList = new ArrayList<TokenValidator>();
        jwtTokenValidatorAList.add(this.jwtTokenValidatorA);

        Collection<TokenValidator> jwtTokenValidatorBList = new ArrayList<TokenValidator>();
        jwtTokenValidatorBList.add(this.jwtTokenValidatorB);

        // URI logic goes here
        if (request.getPath().equals("/endpoint-a")) {
            return Flowable.fromIterable(jwtTokenValidatorAList)
                    .flatMap(tokenValidator -> tokenValidator.validateToken(tokenValue, request))
                    .firstElement()
                    .map(authentication -> {
                        request.setAttribute(TOKEN, tokenValue);
                        eventPublisher.publishEvent(new TokenValidatedEvent(tokenValue));
                        return authentication;
                    }).toFlowable();
        } else if (request.getPath().equals("/endpoint-b")){
//            return Flowable.fromIterable(jwtTokenValidatorAList)
//                    .flatMap(tokenValidator -> tokenValidator.validateToken(tokenValue, request))
//                    .firstElement()
//                    .map(authentication -> {
//                        request.setAttribute(TOKEN, tokenValue);
//                        eventPublisher.publishEvent(new TokenValidatedEvent(tokenValue));
//                        return authentication;
//                    }).toFlowable();
            return Flowable.empty();
        } else {
            return Flowable.empty();
        }
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
