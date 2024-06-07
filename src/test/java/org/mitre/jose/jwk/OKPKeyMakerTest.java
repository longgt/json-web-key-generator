package org.mitre.jose.jwk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;

public class OKPKeyMakerTest {

    @Test
    void sha256() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA256;
        String hashAlg = "SHA-256";
        OctetKeyPair key = OKPKeyMaker.make(Curve.Ed25519, KeyUse.SIGNATURE, JWSAlgorithm.EdDSA, kidGenerator);
        OctetKeyPair ecKey = new OctetKeyPair.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), ecKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha384() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA384;
        String hashAlg = "SHA-384";
        OctetKeyPair key = OKPKeyMaker.make(Curve.Ed25519, KeyUse.SIGNATURE, JWSAlgorithm.EdDSA, kidGenerator);
        OctetKeyPair ecKey = new OctetKeyPair.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), ecKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void sha512() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.SHA512;
        String hashAlg = "SHA-512";
        OctetKeyPair key = OKPKeyMaker.make(Curve.Ed25519, KeyUse.SIGNATURE, JWSAlgorithm.EdDSA, kidGenerator);
        OctetKeyPair ecKey = new OctetKeyPair.Builder(key).keyIDFromThumbprint(hashAlg).build();
        assertEquals(key.getKeyID(), ecKey.getKeyID(),
                "kid should be same as " + hashAlg + " hashed value from method keyIDFromThumbprint");
    }

    @Test
    void uuid() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.UUID;
        OctetKeyPair key = OKPKeyMaker.make(Curve.Ed25519, KeyUse.SIGNATURE, JWSAlgorithm.EdDSA, kidGenerator);
        assertDoesNotThrow(() -> {
            UUID.fromString(key.getKeyID());
        });
    }

}
