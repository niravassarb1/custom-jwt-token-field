package example.micronaut

import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Property
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.test.annotation.MicronautTest
import spock.lang.Specification

import javax.inject.Inject

@Property(name = "b1x.security.jwt-token-per-endpoint.enabled", value = "false")
@MicronautTest
class JwtTokenPerEndpointDisabledTest extends Specification {

    @Inject
    HomeControllerClient appClient

    @Inject
    JwtGeneratorAClient jwtGeneratorAClient;
    @Inject
    JwtGeneratorBClient jwtGeneratorBClient;

    def "verify endpoint-a and endpoint-b are both validated with jwks from jwt-generator-a"() {
        when: 'login and get auth token'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRspFromA = jwtGeneratorAClient.login(creds)

        then:
        loginRspFromA
        loginRspFromA.accessToken
        JWTParser.parse(loginRspFromA.accessToken) instanceof SignedJWT

        when: "accessing endpoint-a with token from jwt-generator-a"
        String msgA = appClient.getEndpointA("Bearer ${loginRspFromA.accessToken}")
        String msgB = appClient.getEndpointB("Bearer ${loginRspFromA.accessToken}")

        then: "authorized"
        msgA == 'sherlockFromA'
        msgB == 'sherlockFromB'
    }

    def "verify endpoint-a and endpoint-b are both validated with jwks from jwt-generator-b"() {
        when: 'login and get auth token'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRspFromB = jwtGeneratorBClient.login(creds)

        then:
        loginRspFromB
        loginRspFromB.accessToken
        JWTParser.parse(loginRspFromB.accessToken) instanceof SignedJWT

        when: "accessing endpoint-a with token from jwt-generator-b"
        String msgA = appClient.getEndpointA("Bearer ${loginRspFromB.accessToken}")
        String msgB = appClient.getEndpointB("Bearer ${loginRspFromB.accessToken}")

        then: "authorized"
        msgA == 'sherlockFromA'
        msgB == 'sherlockFromB'
    }

}
