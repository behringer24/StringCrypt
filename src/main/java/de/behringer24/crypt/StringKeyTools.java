package de.behringer24.crypt;

import android.annotation.TargetApi;
import android.os.Build;
import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * Created by abe on 11.09.2015.
 */
public class StringKeyTools {
    public static final String PKALGORITHM = "RSA/ECB/PKCS1PADDING";
    public static final String PKKEYTYPE = "RSA";

    public static final String SKALGORITHM = "DESede/ECB/PKCS5Padding";
    public static final String SKKEYTYPE = "DESede";

    public static final int KEYLENGTH = 1024;


    /**
     * Create RSA key pair
     * @return KeyPair
     */
    public static KeyPair createKeyPair() throws StringKeyException {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(PKKEYTYPE);
            kpg.initialize(KEYLENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new StringKeyException("Public key algorithm " + PKKEYTYPE + " not available. " + e.getMessage());
        }
        return kpg.genKeyPair();
    }

    /**
     * Generate secret symmetric session key
     * @return SecretKey
     */
    public static SecretKey generateRandomKey() throws StringKeyException {
        SecureRandom random = new SecureRandom();
        final byte[] rawKey = new byte[24];
        random.nextBytes(rawKey);
        return generateKey(rawKey);
    }

    /**
     * Convert byte array to symmetric session key
     * @param rawKey
     * @return SecretKey
     */
    public static SecretKey generateKey(byte[] rawKey) throws StringKeyException {
        try {
            final DESedeKeySpec keyspec = new DESedeKeySpec(rawKey);
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(SKKEYTYPE);
            return keyfactory.generateSecret(keyspec);
        } catch (NoSuchAlgorithmException e) {
            throw new StringKeyException("Symmetric key algorithm " + SKKEYTYPE + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringKeyException("Invalid public key. " + e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new StringKeyException("Invalid key spec. " + e.getMessage());
        }
    }

    /**
     * Convert symmetric session key to byte array
     * @param key
     * @return byte[]
     */
    public static byte[] getRawKey(SecretKey key) {
        try {
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(SKKEYTYPE);
            final DESedeKeySpec keyspec = (DESedeKeySpec) keyfactory.getKeySpec(key, DESedeKeySpec.class);
            return keyspec.getKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Helper function to convert a public or private key to BASE64 encoded String
     * @param key
     * @return String
     */
    @TargetApi(Build.VERSION_CODES.FROYO)
    public static String key2string(Key key) {
        return Base64.encodeToString(key.getEncoded(), Base64.DEFAULT);
    }

    /**
     * Helper function to convert a BASE64 string to a public key
     * @param key
     * @return Key
     * @throws StringCryptException
     */
    @TargetApi(Build.VERSION_CODES.FROYO)
    public static PublicKey string2publickey(String key) throws StringCryptException {
        byte[] encodedKey = Base64.decode(key, Base64.DEFAULT);
        PublicKey result = null;

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encodedKey);

        try {
            KeyFactory keyFact = KeyFactory.getInstance(PKKEYTYPE, "BC");
            result = keyFact.generatePublic(x509KeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Helper function to convert a BASE64 string to a private RSA key
     * @param key
     * @return Key
     * @throws StringCryptException
     */
    @TargetApi(Build.VERSION_CODES.FROYO)
    public static PrivateKey string2privatekey(String key) throws StringCryptException {
        byte[] encodedKey = Base64.decode(key, Base64.DEFAULT);
        PrivateKey result = null;

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(encodedKey);

        try {
            KeyFactory keyFact = KeyFactory.getInstance(PKKEYTYPE);
            result = keyFact.generatePrivate(pkcs8KeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }

}
