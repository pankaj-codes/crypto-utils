package com.pankaj.crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import jakarta.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionUtilsTest {

    @Test
    void generateAESKey() throws NoSuchAlgorithmException {
        SecretKey key = SymmetricEncryptionUtils.generateAESKey();
        assertNotNull(key);
        System.out.println(key);
        System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));
    }

    @Test
    void testAESCryptoRoutine() throws Exception{
        SecretKey secretKey = SymmetricEncryptionUtils.generateAESKey();
        byte[] iv = SymmetricEncryptionUtils.createInitializationVector();
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = SymmetricEncryptionUtils.performAESEncryption(plainText, secretKey, iv);
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));

        String decryptedText = SymmetricEncryptionUtils.performAESDecryption(cipherText, secretKey, iv);

        assertEquals(plainText, decryptedText);

        //If you get an error invalid key size it means jdk doesn't have the "unlimited strength"
    }
}