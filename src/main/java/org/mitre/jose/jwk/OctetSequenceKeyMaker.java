/**
 *
 */
package org.mitre.jose.jwk;

import java.security.SecureRandom;
import java.util.LinkedHashMap;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 */
public class OctetSequenceKeyMaker {

    /**
     * @param keySize in bits
     * @return
     */
    public static OctetSequenceKey make(Integer keySize, KeyUse use, Algorithm alg, KeyIdGenerator kid) {

        // holder for the random bytes
        byte[] bytes = new byte[keySize / 8];

        // make a random number generator and fill our holder
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(bytes);

        Base64URL encoded = Base64URL.encode(bytes);

        LinkedHashMap<String, Object> requiredParams = new LinkedHashMap<>();
        requiredParams.put(JWKParameterNames.OCT_KEY_VALUE, encoded.toString());
        requiredParams.put(JWKParameterNames.KEY_TYPE, KeyType.OCT.getValue());

        // make a key
        OctetSequenceKey octetSequenceKey = new OctetSequenceKey.Builder(encoded)
                .keyID(kid.generate(requiredParams))
                .algorithm(alg)
                .keyUse(use)
                .build();

        return octetSequenceKey;
    }

}
