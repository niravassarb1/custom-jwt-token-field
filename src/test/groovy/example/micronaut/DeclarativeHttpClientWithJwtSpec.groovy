package example.micronaut

import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.test.annotation.MicronautTest
import spock.lang.Specification

import javax.inject.Inject

@MicronautTest
class DeclarativeHttpClientWithJwtSpec extends Specification {

    @Inject
    AppClient appClient // <1>

    def "verify token can authorize through Authorization: Bearer"() {
        when: 'Login endpoint is called with valid credentials'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRsp = appClient.login(creds)

        then:
        loginRsp
        loginRsp.accessToken
        JWTParser.parse(loginRsp.accessToken) instanceof SignedJWT

        when: "accessing an endpoint; header is blank and sending the token through a http param"
        String msg = appClient.accessWithTokenHeader("Bearer ${loginRsp.accessToken}")

        then:
        msg == 'sherlock'
    }

    def "verify token can be used from a http param"() {
        when: 'Login endpoint is called with valid credentials'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password")
        BearerAccessRefreshToken loginRsp = appClient.login(creds)

        then:
        loginRsp
        loginRsp.accessToken
        JWTParser.parse(loginRsp.accessToken) instanceof SignedJWT

        when: "accessing an endpoint; header is blank and sending the token through a http param"
        String msg = appClient.accessWithTokenParam(loginRsp.accessToken)

        then:
        msg == 'sherlock'
    }


}
