package example.micronaut;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.security.Principal;

@JwtTokenPerEndpoint("nirav")
@Secured(SecurityRule.IS_AUTHENTICATED)
@Controller
public class HomeController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get(value = "/endpoint-a")
    public String getEndpointA(Principal principal) {
        return principal.getName()+"FromA";
    }

    @Produces(MediaType.TEXT_PLAIN)
    @Get(value = "/endpoint-b")
    public String getEndpointB(Principal principal) {
        return principal.getName()+"FromB";
    }
}
