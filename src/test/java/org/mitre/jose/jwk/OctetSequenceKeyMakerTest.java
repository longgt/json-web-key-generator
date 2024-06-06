package org.mitre.jose.jwk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;

public class OctetSequenceKeyMakerTest {

    @Test
    void sha256() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA256;
        String hashAlg = "SHA-256";
        OctetSequenceKey key = OctetSequenceKeyMaker.make(2048, KeyUse.SIGNATURE, JWSAlgorithm.HS256, kidGenerator);
        OctetSequenceKey octKey = new OctetSequenceKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), octKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha384() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA384;
        String hashAlg = "SHA-384";
        OctetSequenceKey key = OctetSequenceKeyMaker.make(2048, KeyUse.SIGNATURE, JWSAlgorithm.HS256, kidGenerator);
        OctetSequenceKey octKey = new OctetSequenceKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), octKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha512() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA512;
        String hashAlg = "SHA-512";
        OctetSequenceKey key = OctetSequenceKeyMaker.make(2048, KeyUse.SIGNATURE, JWSAlgorithm.HS256, kidGenerator);
        OctetSequenceKey octKey = new OctetSequenceKey.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), octKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

}
