package com.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class PGPMain {

    public static void main(String[] args) {
        rsaExample();
    }

    private static void rsaExample() {
        int keySize = 1024;

        String keyAlgorithm = "RSA";
        //String messageAlgorithm = "RSA";
        //String messageAlgorithm = "RSA/None/OAEPWithSHA1AndMGF1Padding";
        //String messageAlgorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        String messageAlgorithm = "RSA/ECB/PKCS1Padding";

        KeyPair singleKeyPair = getKeyPair(keyAlgorithm, keySize);


        byte[] input = "abc".getBytes();
        byte[] encrypted = encrypt(messageAlgorithm, singleKeyPair.getPublic(), input);
        System.out.println(new String(encrypted));

        byte[] decrypted = decrypt(messageAlgorithm, singleKeyPair.getPrivate(), encrypted);
        System.out.println(new String(decrypted));
    }

    private static byte[] decrypt(String messageAlgorithm, Key key, byte[] input) {
        try {
            Cipher instance = Cipher.getInstance(messageAlgorithm);
            instance.init(Cipher.DECRYPT_MODE, key);
            return instance.doFinal(input);
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

    private static byte[] encrypt(String messageAlgorithm, Key key, byte[] input) {
        try {
            Cipher instance = Cipher.getInstance(messageAlgorithm);
            instance.init(Cipher.ENCRYPT_MODE, key);
            return instance.doFinal(input);
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

    private static KeyPair getKeyPair(String keyAlgorith, int keySize) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorith);
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
