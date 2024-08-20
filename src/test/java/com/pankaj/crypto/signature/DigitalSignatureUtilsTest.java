package com.pankaj.crypto.signature;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import com.pankaj.crypto.asymmetric.AsymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;
import jakarta.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DigitalSignatureUtilsTest {

    @Test
    void digitalSignatureRoutine() throws Exception {
        URL url = this.getClass().getClassLoader().getResource("demo.txt");
        assert url != null;
        Path path = Paths.get(url.toURI());
        byte[] input = Files.readAllBytes(path);

        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        byte[] signature = DigitalSignatureUtils.createDigitalSignature(input, keyPair.getPrivate());
        System.out.println(DatatypeConverter.printHexBinary(signature));
        assertTrue(DigitalSignatureUtils.verifyDigitalSignature(input, signature, keyPair.getPublic()));
    }

}