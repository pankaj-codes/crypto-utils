package com.pankaj.crypto;

import com.pankaj.crypto.fips.FIPSNonCompliantCode;

public class Main {
    public static void main(String[] args) {

        try {

//            for (Provider provider : Security.getProviders()){
//                if (!provider.getName().equalsIgnoreCase("BCFIPS")){
//
//                    Security.removeProvider(provider.getName());
//                    System.out.println(provider.getName());
//                }
//            }

            // This should be enabled for FIPS enablement.
            System.setProperty("org.bouncycastle.fips.approved_only", "true");

            // This will fail and give BC exception.
            FIPSNonCompliantCode.fipsNonCompliantKey();

            /* ******************* */

//            KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
//            System.out.println("Asymmetric key creation");
//            System.out.println("Private Key :" + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
//            System.out.println("Public Key :" + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));

            /* ******************* */

//            SecretKey key = SymmetricEncryptionUtils.generateAESKey();
//            System.out.println("Symmetric key creation");
//            System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));

            /* ******************* */

        }
        catch(Exception ex){
            System.out.println("Exception occurred" + ex);
        }
    }
}
