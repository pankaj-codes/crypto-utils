package com.pankaj.crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricEncryptionUtils {

    //Algo that we will be using.
    private static final String AES = "AES";

    /**
     * AES = Name of the ALgo
     * CBC = Continuous Block Chaining
     * PKCS5Padding = Padding in the Cipher
     */
    private static final String AES_CIPHER_ALGO = "AES/CBC/PKCS5Padding";

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();

        // Key generator using the algo we passed.
        // KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("BLOWFISH");

        //Initialize key with the 256 key size and secure random for seeding.
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

    /**
     * The createInitializationVector method in the SymmetricEncryptionUtils class is responsible for generating a random
     * Initialization Vector (IV) for use in cryptographic operations. An IV is a fixed-size input to a cryptographic
     * primitive that is typically required to be random or pseudorandom.
     * <p>
     * We are using CBC {@link #AES_CIPHER_ALGO} therefore need of initialization vector.
     */
    public static byte[] createInitializationVector(){

        // This length is chosen because the AES block size is 16 bytes (128 bits). IV = initialization Vector
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();

        // The nextBytes method of the SecureRandom instance is then called to fill the initializationVector array with
        // random bytes:
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static byte[] performAESEncryption(String plainText, SecretKey secretKey, byte[] initializationVector)
            throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGO);

        // By creating an IvParameterSpec object, the code ensures that the cryptographic operations can use the specified IV,
        // which is essential for modes of operation like CBC (Cipher Block Chaining) that require an IV to function correctly.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    /**
     * @param initializationVector Same IV is needed that was used for encryption
     */
    public static String performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector)
            throws Exception {
        Cipher cipher =  Cipher.getInstance(AES_CIPHER_ALGO);

        // By creating an IvParameterSpec object, the code ensures that the cryptographic operations can use the specified IV,
        // which is essential for modes of operation like CBC (Cipher Block Chaining) that require an IV to function correctly.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

}