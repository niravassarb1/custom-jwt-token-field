package example.micronaut;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.security.Principal;

@Secured(SecurityRule.IS_AUTHENTICATED) // <1>
@Controller
public class HomeController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get
    public String accessWithTokenHeader(Principal principal) {  // <4>
        return principal.getName();
    }

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/accessWithTokenParam")
    public String accessWithTokenParam(Principal principal, String customJwtTokenParam) {  // <4>
        return principal.getName();
    }
}
