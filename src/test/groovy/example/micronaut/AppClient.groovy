package example.micronaut

import io.micronaut.context.annotation.Parameter
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Header
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.QueryValue
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken

@Client("/")
interface AppClient {

    @Post("/login")
    BearerAccessRefreshToken login(@Body UsernamePasswordCredentials credentials)

    @Consumes(MediaType.TEXT_PLAIN)
    @Get
    String accessWithTokenHeader(@Header String authorization)

    @Consumes(MediaType.TEXT_PLAIN)
    @Get("/accessWithTokenParam")
    String accessWithTokenParam(@QueryValue String customJwtTokenParam)
}
