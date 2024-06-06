package org.mitre.jose.jwk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

public class RSAKeyMakerTest {

    @Test
    void sha256() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA256;
        String hashAlg = "SHA-256";
        RSAKey key = RSAKeyMaker.make(2048, KeyUse.SIGNATURE, JWSAlgorithm.RS256, kidGenerator);
        RSAKey rsaKey = new RSAKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), rsaKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha384() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA384;
        String hashAlg = "SHA-384";
        RSAKey key = RSAKeyMaker.make(2048, KeyUse.SIGNATURE, JWSAlgorithm.RS256, kidGenerator);
        RSAKey rsaKey = new RSAKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), rsaKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha512() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA512;
        String hashAlg = "SHA-512";
        RSAKey key = RSAKeyMaker.make(2048, KeyUse.SIGNATURE, JWSAlgorithm.RS256, kidGenerator);
        RSAKey rsaKey = new RSAKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), rsaKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

}
