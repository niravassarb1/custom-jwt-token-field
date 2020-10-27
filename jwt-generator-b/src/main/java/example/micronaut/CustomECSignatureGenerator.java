package example.micronaut;

import io.micronaut.context.annotation.Context;
import io.micronaut.security.token.jwt.signature.ec.ECSignatureGenerator;
import io.micronaut.security.token.jwt.signature.ec.ECSignatureGeneratorConfiguration;

import javax.inject.Named;

@Named("generator")
@Context
public class CustomECSignatureGenerator extends ECSignatureGenerator {

    public CustomECSignatureGenerator(ECSignatureGeneratorConfiguration config) {
        super(config);
    }
}
