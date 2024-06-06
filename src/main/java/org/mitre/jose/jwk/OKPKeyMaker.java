package org.mitre.jose.jwk;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 *
 */
public class OKPKeyMaker {

	/**
	 * @param keyCurve
	 * @param keyUse
	 * @param keyAlg
	 * @param kid
	 * @return
	 */
	public static JWK make(Curve keyCurve, KeyUse keyUse, Algorithm keyAlg, KeyIdGenerator kid) {

		try {

			KeyPair keyPair = null;
			if (keyCurve.equals(Curve.Ed25519)) {
				keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
			} else if (keyCurve.equals(Curve.Ed448)) {
				keyPair = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
			} else if (keyCurve.equals(Curve.X25519)) {
				keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
			} else if (keyCurve.equals(Curve.X448)) {
				keyPair = KeyPairGenerator.getInstance("X448").generateKeyPair();
			}

			if (keyPair == null) {
				return null;
			}

			// Java only gives us the keys in ASN.1 format so we need to parse them back out to get the raw numbers

			/*
			 * Public key is:
			 *
			 * SEQUENCE (2 elem)
			 *   SEQUENCE (1 elem)
			 *     OBJECT IDENTIFIER
			 *   BIT STRING (n bit) <-- x value
			 *
			 */
			ASN1Sequence pubPrim = (ASN1Sequence) ASN1Sequence.fromByteArray(keyPair.getPublic().getEncoded());
			byte[] x = ((ASN1BitString)pubPrim.getObjectAt(1)).getOctets();


			/*
			 * Private key is:
			 *
			 * SEQUENCE (4 elem)
			 *   INTEGER
			 *   SEQUENCE (1 elem)
			 *     OBJECT IDENTIFIER
			 *   OCTET STRING (1 elem)
			 *     OCTET STRING (n byte) <-- d value
			 *   OCTET STRING (n byte) <-- (x value)
			 *
			 */
			ASN1Sequence privPrim = (ASN1Sequence) ASN1Sequence.fromByteArray(keyPair.getPrivate().getEncoded());
			byte[] d = ((ASN1OctetString)privPrim.getObjectAt(2)).getOctets();

			// Both the public and private keys should be the same length.
			// For some reason, sometimes the private key is double-wrapped in OctetStrings and we need to unpack that.
			if (x.length < d.length) {
				d = ((ASN1OctetString)ASN1OctetString.fromByteArray(d)).getOctets();
			}

            LinkedHashMap<String, Object> requiredParams = new LinkedHashMap<>();
            requiredParams.put(JWKParameterNames.OKP_SUBTYPE, keyCurve.toString());
            requiredParams.put(JWKParameterNames.KEY_TYPE, KeyType.OKP.getValue());
            requiredParams.put(JWKParameterNames.OKP_PUBLIC_KEY, Base64URL.encode(x).toString());

			// Now that we have the raw numbers, export them as a JWK
			OctetKeyPair jwk = new OctetKeyPair.Builder(keyCurve, Base64URL.encode(x))
				.d(Base64URL.encode(d))
				.keyUse(keyUse)
				.algorithm(keyAlg)
                    .keyID(kid.generate(requiredParams))
				.build();

			return jwk;

		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}


	}

}
