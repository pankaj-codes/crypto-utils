package com.pankaj.crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
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
        String plainText = "This is the text we are going to hide in plain sight";
        String cipherText = SymmetricEncryptionUtils.performAESEncryption(plainText, secretKey);
        assertNotNull(cipherText);
        System.out.println(cipherText);
        String[] parts = cipherText.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        String decryptedText = SymmetricEncryptionUtils.performAESDecryption(cipherText, secretKey);
        assertEquals(plainText, decryptedText);

        //If you get an error invalid key size it means jdk doesn't have the "unlimited strength"
    }
}