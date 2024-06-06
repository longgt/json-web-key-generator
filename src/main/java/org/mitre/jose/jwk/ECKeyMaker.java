/**
 *
 */
package org.mitre.jose.jwk;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.LinkedHashMap;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 */
public class ECKeyMaker {

    /**
     * @param crv
     * @param keyUse
     * @param keyAlg
     * @param kid
     * @return
     */
    public static ECKey make(Curve crv, KeyUse keyUse, Algorithm keyAlg, KeyIdGenerator kid) {

        try {
            ECParameterSpec ecSpec = crv.toECParameterSpec();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(ecSpec);

            KeyPair kp = generator.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();

            Base64URL x = ECKey.encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX());
            Base64URL y = ECKey.encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY());

            LinkedHashMap<String, Object> requiredParams = new LinkedHashMap<>();
            requiredParams.put(JWKParameterNames.ELLIPTIC_CURVE, crv.toString());
            requiredParams.put(JWKParameterNames.KEY_TYPE, KeyType.EC.getValue());
            requiredParams.put(JWKParameterNames.ELLIPTIC_CURVE_X_COORDINATE, x.toString());
            requiredParams.put(JWKParameterNames.ELLIPTIC_CURVE_Y_COORDINATE, y.toString());

            ECKey ecKey = new ECKey.Builder(crv, pub)
                    .privateKey(priv)
                    .keyID(kid.generate(requiredParams))
                    .algorithm(keyAlg)
                    .keyUse(keyUse)
                    .build();

            return ecKey;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

    }

}
