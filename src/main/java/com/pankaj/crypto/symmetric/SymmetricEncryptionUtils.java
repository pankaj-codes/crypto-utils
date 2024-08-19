package com.pankaj.crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SymmetricEncryptionUtils {

    //Algo that we will be using.
    private static final String AES = "AES";

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();

        //Key generator using the algo we passed.
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);

        //Initialize key with the 256 key size and secure random for seeding.
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

}