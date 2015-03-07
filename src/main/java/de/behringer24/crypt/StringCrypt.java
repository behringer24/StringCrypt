package de.behringer24.crypt;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * Class for easy string encryption without the length limitations of RSA cryptography
 * Created by Andreas Behringer on 03/07/2015
 *
 * Usage:
 * StringCrypt crypt = new StringCrypt();
 *
 * KeyPair kp = crypt.createKeyPair();
 * Key privateKey = kp.getPrivate();
 * Key publicKey = kp.getPublic();
 *
 * CryptPackage cryptPackage = crypt.encrypt(message, publicKey);
 * String packageString = cryptPackage.toString();
 * // Do something with packageString, eg network transmit
 * CryptPackage newPackage = new CryptPackage(packageString);
 * String decryptedString = crypt.decrypt(newPackage, privateKey);
 */
public class StringCrypt {
    private static final String PKALGORITHM = "RSA/ECB/PKCS1PADDING";
    private static final String SKALGORITHM = "DESede/ECB/PKCS5Padding";
    private static final int KEYLENGTH = 1024;

    /**
     * Encrypt message with publicKey
     * @param message
     * @param publicKey
     * @return CryptPackage
     */
    public CryptPackage encrypt(String message, Key publicKey) {
        byte[] inputBytes = message.getBytes();
        byte[] encryptedMessage = null;
        byte[] encryptedSymmetricKey = null;
        final SecretKey sessionKey = generateRandomKey();

        try {
            // encrypt symmetric session key with public key
            Cipher publicKeyCipher = Cipher.getInstance(PKALGORITHM);
            publicKeyCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedSymmetricKey = publicKeyCipher.doFinal(getRawKey(sessionKey));

            // encrypt message with session key
            Cipher symmetricCipher = Cipher.getInstance(SKALGORITHM);
            symmetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            encryptedMessage = symmetricCipher.doFinal(inputBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new CryptPackage(encryptedMessage, encryptedSymmetricKey);
    }

    /**
     * Decrypt message in cryptPackage with privateKey
     * @param cryptPackage
     * @param privateKey
     * @return String
     */
    public String decrypt(CryptPackage cryptPackage, Key privateKey) {
        String decrypedString = null;

        try {
            // decrypt symmetric session key with private key
            Cipher publicKeyCipher = Cipher.getInstance(PKALGORITHM);
            publicKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] rawKey = publicKeyCipher.doFinal(cryptPackage.getEncryptedSymmetricKey());
            SecretKey symmetricKey = generateKey(rawKey);

            // decrpyt message with symmetric key
            Cipher cipher = Cipher.getInstance(SKALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            final byte[] decrypedBytes = cipher.doFinal(cryptPackage.getEncryptedMessage());
            decrypedString = new String(decrypedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypedString;
    }

    /**
     * Create RSA key pair
     * @return KeyPair
     */
    public KeyPair createKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEYLENGTH);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return kpg.genKeyPair();
    }

    /**
     * Generate secret symmetric session key
     * @return SecretKey
     */
    private SecretKey generateRandomKey() {
        SecureRandom random = new SecureRandom();
        try {
            final byte[] rawKey = new byte[24];
            random.nextBytes(rawKey);
            return generateKey(rawKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Convert byte array to symmetric session key
     * @param rawKey
     * @return SecretKey
     */
    private SecretKey generateKey(byte[] rawKey) {
        try {
            final DESedeKeySpec keyspec = new DESedeKeySpec(rawKey);
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
            return keyfactory.generateSecret(keyspec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Convert symmetric session key to byte array
     * @param key
     * @return byte[]
     */
    private byte[] getRawKey(SecretKey key) {
        try {
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
            final DESedeKeySpec keyspec = (DESedeKeySpec) keyfactory.getKeySpec(key, DESedeKeySpec.class);
            return keyspec.getKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

