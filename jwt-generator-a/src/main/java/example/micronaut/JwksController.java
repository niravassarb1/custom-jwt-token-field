package example.micronaut;

import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import one.block.b1x.utils.security.jwt.Jwk;

import javax.inject.Inject;

@Secured(SecurityRule.IS_ANONYMOUS)
@Controller
public class JwksController {

//    @Inject
//    ECSignatureGeneratorConfiguration ecSignatureGeneratorConfiguration;

    @Inject
    Jwk jwk;

    @Produces(MediaType.APPLICATION_JSON)
    @Get("/.well-known/jwks.json")
    public String getJwks() {
        return new JWKSet(jwk.getEcKey()).toPublicJWKSet().toString();
    }
}
