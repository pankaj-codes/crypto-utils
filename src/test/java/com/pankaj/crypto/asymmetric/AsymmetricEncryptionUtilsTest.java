package com.pankaj.crypto.asymmetric;

import java.security.KeyPair;

import org.junit.jupiter.api.Test;

import jakarta.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricEncryptionUtilsTest {

    @Test
    void generateRSAKeyPair() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        assertNotNull(keyPair);
        System.out.println("Private Key :" + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key :" + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
    }
}