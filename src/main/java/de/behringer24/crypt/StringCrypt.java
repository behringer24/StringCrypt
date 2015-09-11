package de.behringer24.crypt;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

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

    /**
     * Encrypt message with publicKey
     * @param message
     * @param publicKey
     * @return CryptPackage
     */
    public CryptPackage encrypt(String message, Key publicKey) throws StringCryptException, StringKeyException {
        byte[] inputBytes = message.getBytes();
        byte[] encryptedMessage = null;
        byte[] encryptedSymmetricKey = null;
        final SecretKey sessionKey = StringKeyTools.generateRandomKey();

        try {
            // encrypt symmetric session key with public key
            Cipher publicKeyCipher = Cipher.getInstance(StringKeyTools.PKALGORITHM);
            publicKeyCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedSymmetricKey = publicKeyCipher.doFinal(StringKeyTools.getRawKey(sessionKey));
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + StringKeyTools.PKALGORITHM + " not available. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + StringKeyTools.PKALGORITHM + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        try {
            // encrypt message with session key
            Cipher symmetricCipher = Cipher.getInstance(StringKeyTools.SKALGORITHM);
            symmetricCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            encryptedMessage = symmetricCipher.doFinal(inputBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Symmetric crypto algorithm " + StringKeyTools.PKALGORITHM + " not available");
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + StringKeyTools.PKALGORITHM + " not available");
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
    public String decrypt(CryptPackage cryptPackage, Key privateKey) throws StringCryptException, StringKeyException {
        String decrypedString = null;
        SecretKey symmetricKey = null;

        // decrypt symmetric session key with private key
        try {
            Cipher publicKeyCipher = Cipher.getInstance(StringKeyTools.PKALGORITHM);
            publicKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] rawKey = publicKeyCipher.doFinal(cryptPackage.getEncryptedSymmetricKey());
            symmetricKey = StringKeyTools.generateKey(rawKey);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + StringKeyTools.PKALGORITHM + " not available. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + StringKeyTools.PKALGORITHM + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        // decrpyt message with symmetric key
        try {
            Cipher cipher = Cipher.getInstance(StringKeyTools.SKALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            final byte[] decrypedBytes = cipher.doFinal(cryptPackage.getEncryptedMessage());
            decrypedString = new String(decrypedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new StringCryptException("Public key algorithm " + StringKeyTools.PKALGORITHM + " not available. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new StringCryptException("Padding algorithm " + StringKeyTools.PKALGORITHM + " not available. " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new StringCryptException("Invalid public key. " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new StringCryptException("Invalid block size. " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new StringCryptException("Bad padding. " + e.getMessage());
        }

        return decrypedString;
    }
}

