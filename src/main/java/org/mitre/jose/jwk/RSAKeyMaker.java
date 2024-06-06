/**
 *
 */
package org.mitre.jose.jwk;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 */
public class RSAKeyMaker {

    /**
     * @param keySize
     * @param keyUse
     * @param keyAlg
     * @param kid
     * @return
     */
    public static RSAKey make(Integer keySize, KeyUse keyUse, Algorithm keyAlg, KeyIdGenerator kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair kp = generator.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();

            Base64URL n = Base64URL.encode(pub.getModulus());
            Base64URL e = Base64URL.encode(pub.getPublicExponent());

            LinkedHashMap<String, Object> requiredParams = new LinkedHashMap<>();
            requiredParams.put(JWKParameterNames.RSA_EXPONENT, e.toString());
            requiredParams.put(JWKParameterNames.KEY_TYPE, KeyType.RSA.getValue());
            requiredParams.put(JWKParameterNames.RSA_MODULUS, n.toString());

            RSAKey rsaKey = new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(keyUse)
                    .algorithm(keyAlg)
                    .keyID(kid.generate(requiredParams))
                    .build();

            return rsaKey;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}
