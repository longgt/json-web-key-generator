package org.mitre.jose.jwk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.github.f4b6a3.uuid.UuidCreator;
import com.github.f4b6a3.uuid.enums.UuidVersion;
import com.github.f4b6a3.uuid.exception.InvalidUuidException;
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

    @Test
    void uuid() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.UUIDv4;
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        assertDoesNotThrow(() -> {
            if (UuidCreator.fromString(key.getKeyID()).version() != UuidVersion.VERSION_RANDOM_BASED.getValue()) {
                throw new InvalidUuidException("Invalid UUIDv4");
            }
        });
    }

    @Test
    void uuidv1() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.UUIDv1;
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        assertDoesNotThrow(() -> {
            if (UuidCreator.fromString(key.getKeyID()).version() != UuidVersion.VERSION_TIME_BASED.getValue()) {
                throw new InvalidUuidException("Invalid UUIDv1");
            }
        });
    }

    @Test
    void uuidv6() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.UUIDv6;
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        assertDoesNotThrow(() -> {
            if (UuidCreator.fromString(key.getKeyID()).version() != UuidVersion.VERSION_TIME_ORDERED.getValue()) {
                throw new InvalidUuidException("Invalid UUIDv6");
            }
        });
    }

    @Test
    void uuidv7() throws JOSEException {
        KeyIdGenerator kidGenerator = KeyIdGenerator.UUIDv7;
        ECKey key = ECKeyMaker.make(Curve.P_256, KeyUse.SIGNATURE, JWSAlgorithm.ES256, kidGenerator);
        assertDoesNotThrow(() -> {
            if (UuidCreator.fromString(key.getKeyID()).version() != UuidVersion.VERSION_TIME_ORDERED_EPOCH.getValue()) {
                throw new InvalidUuidException("Invalid UUIDv7");
            }
        });
    }

}
