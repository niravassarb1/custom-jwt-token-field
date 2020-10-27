package example.micronaut;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import io.micronaut.context.annotation.Context;
import io.micronaut.security.token.jwt.signature.ec.ECSignatureGeneratorConfiguration;
import one.block.b1x.utils.security.jwt.Jwk;

import javax.inject.Inject;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Context
public class CustomECSignatureGeneratorConfiguration implements ECSignatureGeneratorConfiguration {
    @Inject
    Jwk jwk;

    @Override
    public ECPrivateKey getPrivateKey() {
        try {
            return jwk.getEcKey().toECPrivateKey();
        } catch (JOSEException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public ECPublicKey getPublicKey() {
        try {
            return jwk.getEcKey().toECPublicKey();
        } catch (JOSEException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public JWSAlgorithm getJwsAlgorithm() {
        return JWSAlgorithm.parse(jwk.getEcKey().getAlgorithm().getName());
    }
}
