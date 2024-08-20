package com.pankaj.crypto.hash;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.mindrot.jbcrypt.BCrypt;

public class HashUtils {

    private static final String SHA2_ALGO = "SHA-256";

    /**
     * Since Hashing is susceptible to RAINBOW attacks therefore SALT is used.
     */
    public static byte[] generateRandomSalt(){
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] createSHA2Hash(String input, byte[] salt) throws Exception{
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // This is a way to write multiple byte arrays to a single byte array.
        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(input.getBytes());
        byte[] valueToHash = byteArrayOutputStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGO);
        return messageDigest.digest(valueToHash);
    }

    public static String hashPassword(String password){
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String password, String hashPassword){
        return BCrypt.checkpw(password, hashPassword);
    }
}
