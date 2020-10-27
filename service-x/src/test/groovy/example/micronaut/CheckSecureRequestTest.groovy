package example.micronaut

import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.test.annotation.MicronautTest
import spock.lang.Specification

import javax.inject.Inject

@MicronautTest
class CheckSecureRequestTest extends Specification {

    @Inject
    AppClient appClient

    @Inject
    JwtGeneratorAClient jwtGeneratorAClient;
    @Inject
    JwtGeneratorBClient jwtGeneratorBClient;


    def "verify app endpoints are available with auth token from jwt-generator-a"() {
        when: 'login and get auth token'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRsp = jwtGeneratorAClient.login(creds)

        then:
        loginRsp
        loginRsp.accessToken
        JWTParser.parse(loginRsp.accessToken) instanceof SignedJWT

        when: "accessing the endpoints A and B providing auth token"

        //Once POC is in place, getEndpoint A should pass and getEndpoint B should get UNAUTHORIZED
        String msgA = appClient.getEndpointA("Bearer ${loginRsp.accessToken}")
        String msgB = appClient.getEndpointB("Bearer ${loginRsp.accessToken}")

        then:
        msgA == 'sherlock'
        msgB == 'sherlock'
    }

    def "verify app endpoints are available with auth token from jwt-generator-b"() {
        when: 'login and get auth token'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRsp = jwtGeneratorBClient.login(creds)

        then:
        loginRsp
        loginRsp.accessToken
        JWTParser.parse(loginRsp.accessToken) instanceof SignedJWT

        when: "accessing the endpoints A and B providing auth token"

        //Once POC is in place, getEndpoint B should pass and getEndpoint A should get UNAUTHORIZED
        String msgA = appClient.getEndpointA("Bearer ${loginRsp.accessToken}")
        String msgB = appClient.getEndpointB("Bearer ${loginRsp.accessToken}")

        then:
        msgA == 'sherlock'
        msgB == 'sherlock'
    }

}
