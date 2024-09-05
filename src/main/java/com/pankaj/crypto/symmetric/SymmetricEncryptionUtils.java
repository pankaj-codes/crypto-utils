package com.pankaj.crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
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
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        // KeyGenerator keyGenerator = KeyGenerator.getInstance("BLOWFISH");

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
    public static byte[] createInitializationVector(int blockSize){

        // This length is chosen because the AES block size is 16 bytes (128 bits). IV = initialization Vector
        byte[] initializationVector = new byte[blockSize];
        SecureRandom secureRandom = new SecureRandom();

        // The nextBytes method of the SecureRandom instance is then called to fill the initializationVector array with
        // random bytes:
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static String performAESEncryption(String plainText, SecretKey secretKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGO);

        /*
          For AES algo, block size is 128 bits i.e. 16 bytes
         */
        byte[] initializationVector = createInitializationVector(cipher.getBlockSize());

        // By creating an IvParameterSpec object, the code ensures that the cryptographic operations can use the specified IV,
        // which is essential for modes of operation like CBC (Cipher Block Chaining) that require an IV to function correctly.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(initializationVector) + ":" + Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * Same IV is needed that was used for encryption
     */
    public static String performAESDecryption(String cipherText, SecretKey secretKey)
            throws Exception {
        Cipher cipher =  Cipher.getInstance(AES_CIPHER_ALGO);

        String[] parts = cipherText.split(":");

        byte[] initializationVector = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        // By creating an IvParameterSpec object, the code ensures that the cryptographic operations can use the specified IV,
        // which is essential for modes of operation like CBC (Cipher Block Chaining) that require an IV to function correctly.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(encrypted);
        return new String(result);
    }

}