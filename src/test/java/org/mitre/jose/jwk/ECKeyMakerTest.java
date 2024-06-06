package org.mitre.jose.jwk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

public class ECKeyMakerTest {

    @Test
    void sha256() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA256;
        String hashAlg = "SHA-256";
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        ECKey ecKey = new ECKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), ecKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha384() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA384;
        String hashAlg = "SHA-384";
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        ECKey ecKey = new ECKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), ecKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha512() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA512;
        String hashAlg = "SHA-512";
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        ECKey ecKey = new ECKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), ecKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

}
