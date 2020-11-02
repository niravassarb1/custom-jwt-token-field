package example.micronaut;

import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;

import javax.inject.Singleton;
import java.util.Optional;

@Singleton
public class JwtTokenPerEndpointAnnotationRule {

    public String getJwksSignatureName(RouteMatch<?> routeMatch) {
        if (routeMatch instanceof MethodBasedRouteMatch) {
            MethodBasedRouteMatch methodRoute = ((MethodBasedRouteMatch) routeMatch);
            if (methodRoute.hasAnnotation(JwtTokenPerEndpoint.class)) {
                Optional<String> optionalValue = methodRoute.getValue(JwtTokenPerEndpoint.class, String.class);
                if (optionalValue.isPresent()) {
                    String value = optionalValue.get();
                    return value;
                }
            }
        }
        return null;
    }
}
