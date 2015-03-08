package de.behringer24.crypt;

import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Created by andi on 08.03.2015.
 */
public class StringSign {
    public final String SIGALGORITHM = "SHA1WithRSA";

    public String sign(String message, PrivateKey privateKey) throws StringSignException {
        try {
            byte[] data = message.getBytes();

            Signature sig = Signature.getInstance(SIGALGORITHM);
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signatureBytes = sig.sign();

            return Base64.encodeToString(signatureBytes, Base64.DEFAULT);
        } catch (NoSuchAlgorithmException e) {
            throw new StringSignException("Unknown signature algorithm " + SIGALGORITHM);
        } catch (InvalidKeyException e) {
            throw new StringSignException("Invalid key");
        } catch (SignatureException e) {
            throw new StringSignException("Signing failed: " + e.toString());
        }
    }

    public Boolean verify(String message, String signature, PublicKey publicKey) throws StringSignException {
        try {
            byte[] data = message.getBytes();
            byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);

            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initVerify(publicKey);
            sig.update(data);

            return sig.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new StringSignException("Unknown signature algorithm " + SIGALGORITHM);
        } catch (InvalidKeyException e) {
            throw new StringSignException("Invalid key");
        } catch (SignatureException e) {
            throw new StringSignException("Signing failed: " + e.toString());
        }
    }
}
