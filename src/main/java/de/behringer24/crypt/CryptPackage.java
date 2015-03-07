package de.behringer24.crypt;

import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Class to package encrypted message and encrypted symmetric session key into base64 string and back
 * Created by Andreas Behringer on 03/07/2015
 *
 * Usage
 *
 */
public class CryptPackage {
    private final byte[] encryptedMessage;
    private final byte[] encryptedSymmetricKey;

    /**
     * Construct from two byte arrays
     * @param encryptedMessage
     * @param encryptedSymmetricKey
     */
    public CryptPackage(byte[] encryptedMessage, byte[] encryptedSymmetricKey) {
        this.encryptedMessage = encryptedMessage;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
    }

    /**
     * Construct from packed base64 encoded string
     * @param input
     */
    public CryptPackage(String input) {
        final byte[] inputBytes = Base64.decode(input, Base64.DEFAULT);
        final DataInputStream stream = new DataInputStream(new ByteArrayInputStream(inputBytes));

        this.encryptedMessage = readByteArray(stream);
        this.encryptedSymmetricKey = readByteArray(stream);
    }

    /**
     * Getter for encrypted message as byte array
     * @return byte[]
     */
    public byte[] getEncryptedMessage() {
        return this.encryptedMessage;
    }

    /**
     * Getter for encrypted symmetric session key as byte array
     * @return byte[]
     */
    public byte[] getEncryptedSymmetricKey() {
        return this.encryptedSymmetricKey;
    }

    /**
     * Convert whole crypt package into byte array
     * @return byte[]
     */
    public byte[] toByteArray() {
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            final DataOutputStream dataOutputStream = new DataOutputStream(stream);
            dataOutputStream.writeInt(encryptedMessage.length);
            dataOutputStream.write(encryptedMessage);
            dataOutputStream.writeInt(encryptedSymmetricKey.length);
            dataOutputStream.write(encryptedSymmetricKey);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return stream.toByteArray();
    }

    /**
     * Convert whole crypt package into base64 encoded string
     * @return String
     */
    public String toString() {
        return Base64.encodeToString(toByteArray(), Base64.DEFAULT);
    }

    /**
     * Read part of byte array prefixed by length from input stream
     * @param stream
     * @return byte[]
     */
    private byte[] readByteArray(DataInputStream stream)  {
        int length = 0;

        try {
            length = stream.readInt();
            if (length < 0) {

            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        final byte[] bytes = new byte[length];
        final int nrBytesRead;
        try {
            nrBytesRead = stream.read(bytes);
            if (length != nrBytesRead) {

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bytes;
    }
}
