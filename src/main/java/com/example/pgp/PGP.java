package com.example.pgp;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class PGP {

    private byte[] messageKey;

    public byte[] getMessage(String algorithm, int keySize) {

        messageKey = getMessageKey(algorithm, keySize);
        System.out.println(messageKey);

        return new byte[0];
    }

    public byte[] getSignature() {
        return new byte[0];
    }

    public byte[] getKey() {
        return new byte[0];
    }

    private byte[] getMessageKey(String algorithm, int keySize) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            keyGenerator.init(keySize);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
