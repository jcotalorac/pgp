package com.example.pgp;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class PGP {

    private Key messageKey;

    public byte[] getMessage(String algorithm, int keySize, byte[] input) {

        messageKey = getMessageKey(algorithm, keySize);
        System.out.println(messageKey);

        byte[] encryptedMessage = encryptMessage(input, messageKey, algorithm);

        return encryptedMessage;
    }

    public byte[] getSignature() {
        return new byte[0];
    }

    public byte[] getKey() {
        return new byte[0];
    }

    private Key getMessageKey(String algorithm, int keySize) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            keyGenerator.init(keySize);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] encryptMessage(byte[] input, Key key, String algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
