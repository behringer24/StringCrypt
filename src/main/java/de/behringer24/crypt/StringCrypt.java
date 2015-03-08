package de.behringer24.crypt;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
    public CryptPackage encrypt(String message, Key publicKey) throws StringCryptException {
        byte[] inputBytes = message.getBytes();
        byte[] encryptedMessage = null;
        byte[] encryptedSymmetricKey = null;
        final SecretKey sessionKey = generateRandomKey();

        try {
            // encrypt symmetric session key with public key
            Cipher publicKeyCipher = Cipher.getInstance(PKALGORITHM);
            publicKeyCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedSymmetricKey = publicKeyCipher.doFinal(getRawKey(sessionKey));
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        try {
            // encrypt message with session key
            Cipher symmetricCipher = Cipher.getInstance(SKALGORITHM);
            symmetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            encryptedMessage = symmetricCipher.doFinal(inputBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Symmetric crypto algorithm " + PKALGORITHM + " not available");
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + PKALGORITHM + " not available");
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        return new CryptPackage(encryptedMessage, encryptedSymmetricKey);
    }

    /**
     * Decrypt message in cryptPackage with privateKey
     * @param cryptPackage
     * @param privateKey
     * @return String
     */
    public String decrypt(CryptPackage cryptPackage, Key privateKey) throws StringCryptException {
        String decrypedString = null;
        SecretKey symmetricKey = null;

        // decrypt symmetric session key with private key
        try {
            Cipher publicKeyCipher = Cipher.getInstance(PKALGORITHM);
            publicKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] rawKey = publicKeyCipher.doFinal(cryptPackage.getEncryptedSymmetricKey());
            symmetricKey = generateKey(rawKey);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        // decrpyt message with symmetric key
        try {
            Cipher cipher = Cipher.getInstance(SKALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            final byte[] decrypedBytes = cipher.doFinal(cryptPackage.getEncryptedMessage());
            decrypedString = new String(decrypedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        return decrypedString;
    }

    /**
     * Create RSA key pair
     * @return KeyPair
     */
    public KeyPair createKeyPair() throws StringCryptException {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEYLENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + PKALGORITHM + " not available. " + e.getMessage());
        }
        return kpg.genKeyPair();
    }

    /**
     * Generate secret symmetric session key
     * @return SecretKey
     */
    private SecretKey generateRandomKey() throws StringCryptException {
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
    private SecretKey generateKey(byte[] rawKey) throws StringCryptException {
        try {
            final DESedeKeySpec keyspec = new DESedeKeySpec(rawKey);
            final SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
            return keyfactory.generateSecret(keyspec);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Symmetric key algorithm DESede not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new StringCryptException("Invalid key spec. " + e.getMessage());
        }
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

