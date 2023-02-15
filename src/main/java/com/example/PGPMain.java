package com.example;

import com.example.pgp.PGP;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class PGPMain {

    public static void main(String[] args) {
        rsaExample();

        int keyMessageSize = 128;
        byte[] inputMessage = "AESMessage".getBytes();
        String secureMessageAlgorithm = "AES";

        PGP pgp = new PGP();

        byte[] securedMessage = pgp.getSecuredMessage(secureMessageAlgorithm, keyMessageSize, inputMessage);
        System.out.println(new String(securedMessage));

        String keyAlgorithm = "RSA";
        String messageAlgorithm = "RSA/ECB/PKCS1Padding";
        String signAlgorithm = "SHA1withRSA";
        int keySize = 1024;
        KeyPair senderKeyPair = getKeyPair(keyAlgorithm, keySize);
        KeyPair receiverKeyPair = getKeyPair(keyAlgorithm, keySize);

        byte[] securedKey = pgp.getKey(messageAlgorithm, receiverKeyPair.getPublic());
        System.out.println(new String(securedKey));
        byte[] signature = pgp.getSignature(signAlgorithm, senderKeyPair.getPrivate(), inputMessage);
        System.out.println(new String(signature));
    }

    private static void hashingKey() {
        byte[] input = "key".getBytes();

        byte[] hashedKey = getHashedKey("MD5");
    }

    private static byte[] getHashedKey(String algorithm) {
        try {
            MessageDigest md5 = MessageDigest.getInstance(algorithm);
            return md5.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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
