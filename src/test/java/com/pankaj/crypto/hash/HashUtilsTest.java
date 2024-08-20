package com.pankaj.crypto.hash;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import jakarta.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilsTest {

    @Test
    void generateRandomSalt() {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);
        System.out.println(DatatypeConverter.printHexBinary(salt));
    }

    @Test
    void createSHA2Hash() throws Exception{
        byte[] salt = HashUtils.generateRandomSalt();
        String valueToHash = UUID.randomUUID().toString();
        byte[] hash = HashUtils.createSHA2Hash(valueToHash, salt);
        assertNotNull(hash);

        // To verify same hash is generated on same input and same salt
        byte[] hash2 = HashUtils.createSHA2Hash(valueToHash, salt);
        assertEquals(DatatypeConverter.printHexBinary(hash), DatatypeConverter.printHexBinary(hash2));
    }
}