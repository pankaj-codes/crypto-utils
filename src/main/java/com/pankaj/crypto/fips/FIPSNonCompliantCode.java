package com.pankaj.crypto.fips;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import jakarta.xml.bind.DatatypeConverter;

public class FIPSNonCompliantCode {

    public static void fipsNonCompliantKey() {

        /**
         *
         * This is adding provider at the last therefore FIPs not enabled.
         * Both ways didn't work, I enabled FIPS in jre by changing java.security file.
         * Security.addProvider(new BouncyCastleFipsProvider());
         * Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
         */

        // Always needed.
        // System.setProperty("org.bouncycastle.fips.approved_only", "true");

        //        for (Provider provider : Security.getProviders()){
        //            Security.removeProvider(provider.getName());
        //            System.out.println(provider.getName());
        //        }

        try {

            // Cipher cipher = Cipher.getInstance("DES"); // DES is not FIPS-compliant - it should FAIL

            // Create a KeyPairGenerator object for generating RSA keys
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("AES", "BCFIPS");

            // Initialize the key pair generator with the key size (e.g., 2048 bits)
//            keyGen.initialize(1024); // 1024 is not FIPS compliant
            keyGen.initialize(2048); // 2048 FIPS compliant

            // Generate the key pair
            KeyPair pair = keyGen.generateKeyPair();

            // Get the public and private keys
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            // Display the keys
            System.out.println("Public Key: " + DatatypeConverter.printHexBinary(publicKey.getEncoded()));
            System.out.println("Private Key: " + DatatypeConverter.printHexBinary(privateKey.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception occurred.");
        }
    }
}
