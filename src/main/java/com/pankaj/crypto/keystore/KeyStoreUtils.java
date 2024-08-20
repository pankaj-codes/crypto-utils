package com.pankaj.crypto.keystore;

import java.security.KeyStore;
import javax.crypto.SecretKey;

public class KeyStoreUtils {

    /**
     * Saving a private key and standard default will not store private key therefore using JCEKS
     */
    private static final String SECRET_KEY_KEYSTORE_TYPE = "JCEKS";

    public static KeyStore createPrivateKeyJavaKeyStore(String keystorePassword, String keyAlias, SecretKey secretKey, String secretKeyPassword) throws Exception{
        KeyStore keyStore = KeyStore.getInstance(SECRET_KEY_KEYSTORE_TYPE);
        keyStore.load(null, keystorePassword.toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(secretKeyPassword.toCharArray());
        KeyStore.SecretKeyEntry priSecretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(keyAlias, priSecretKeyEntry, entryPassword);
        return keyStore;
    }

}
