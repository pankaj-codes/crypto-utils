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
}