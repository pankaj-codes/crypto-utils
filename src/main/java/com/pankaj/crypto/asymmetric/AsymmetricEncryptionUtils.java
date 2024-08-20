package com.pankaj.crypto.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class AsymmetricEncryptionUtils {
    private static final String RSA = "RSA";

    public static KeyPair generateRSAKeyPair() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);

        // To seed it secure random is used
        keyPairGenerator.initialize(4096, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }
}
