package example.micronaut

import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Property
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.test.annotation.MicronautTest
import spock.lang.Specification

import javax.inject.Inject

@Property(name = "b1x.security.jwt-token-per-endpoint.enabled", value = "true")
@MicronautTest
class JwtTokenPerEndpointTest extends Specification {

    @Inject
    AppClient appClient

    @Inject
    JwtGeneratorAClient jwtGeneratorAClient;
    @Inject
    JwtGeneratorBClient jwtGeneratorBClient;

    def "verify endpoint-a is validated with jwks from jwt-generator-a"() {
        when: 'login and get auth token'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRspFromA = jwtGeneratorAClient.login(creds)

        then:
        loginRspFromA
        loginRspFromA.accessToken
        JWTParser.parse(loginRspFromA.accessToken) instanceof SignedJWT

        when: "accessing endpoint-a with token from jwt-generator-a"
        String msgA = appClient.getEndpointA("Bearer ${loginRspFromA.accessToken}")

        then: "authorized"
        msgA == 'sherlockFromA'

//        when: "accessing the endpoint-b with token from jwt-generator-a"
//        appClient.getEndpointB("Bearer ${loginRspFromA.accessToken}")
//
//        then: "unauthorized"
//        HttpClientResponseException ex = thrown()
//        ex.message == "Unauthorized"

    }

    def "verify endpoint-b is validated with jwks from jwt-generator-b"() {
        when: 'login and get auth token'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRspFromB = jwtGeneratorBClient.login(creds)

        then:
        loginRspFromB
        loginRspFromB.accessToken
        JWTParser.parse(loginRspFromB.accessToken) instanceof SignedJWT

        when: "accessing endpoint-b with token from jwt-generator-b"
        String msgB = appClient.getEndpointB("Bearer ${loginRspFromB.accessToken}")

        then: "authorized"
        msgB == 'sherlockFromB'

        when: "accessing the endpoint-a with token from jwt-generator-b"
        appClient.getEndpointA("Bearer ${loginRspFromB.accessToken}")

        then: "unauthorized"
        HttpClientResponseException ex = thrown()
        ex.message == "Unauthorized"

    }

}
