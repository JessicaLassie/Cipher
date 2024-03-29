/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.keys;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * RSA Keys Generators
 */
public class RSAKeysGenerators {
    
    private static final String RSA = "RSA";
    private static final String PUBLIC_KEY = "\\public_key_";
    private static final String PRIVATE_KEY = "\\private_key_";
    private static final String TXT_EXTENSION = ".txt";
    private static final String DATE_FORMAT = "yyyyMMddHHmmss";
    
    private RSAKeysGenerators() {
        throw new IllegalStateException("Utility class");
    }
    
    /**
     * Generate and save the RSA keys
     * @param outputPath the path for save the RSA keys
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException 
     */
    protected static void generateAndSaveRSAKeys(String outputPath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {      
        KeyPair keyPair = generateRSAKeyPair();
        saveRSAKeyPair(keyPair, outputPath);
    }
    
    /**
     * Generate key pair for RSA crypting
     * @return keys pair (private key and public key)
     * @throws NoSuchAlgorithmException
     */
    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(RSA);
        keyGenerator.initialize(2048);        
        return keyGenerator.generateKeyPair();
    }
    
    /**
     * Save private key in a text file
     * @param keyPair RSA key pair who contains private and public keys
     * @param keysFilesPath the path for save the RSA keys
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException 
     * @throws IOException
     */
    private static void saveRSAKeyPair(final KeyPair keyPair, final String keysFilesPath) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        SimpleDateFormat formater = new SimpleDateFormat(DATE_FORMAT);
        final String date = formater.format(new Date());
        
        File privateKeyFile = new File(keysFilesPath + PRIVATE_KEY + date + TXT_EXTENSION);
        File publicKeyFile = new File(keysFilesPath + PUBLIC_KEY + date + TXT_EXTENSION);
        
        KeyFactory factory = KeyFactory.getInstance(RSA);
        RSAPrivateKeySpec rsaPrivateKey = factory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
        RSAPublicKeySpec rsaPublicKey = factory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
        
        if (rsaPrivateKey != null && rsaPublicKey != null) {
            FileOutputStream fosPrivateKey = new FileOutputStream(privateKeyFile);
            BufferedOutputStream bosPrivateKey = new BufferedOutputStream(fosPrivateKey);
            try (ObjectOutputStream outputFilePrivateKey = new ObjectOutputStream(bosPrivateKey)) {
                outputFilePrivateKey.writeObject(rsaPrivateKey.getModulus());
                outputFilePrivateKey.writeObject(rsaPrivateKey.getPrivateExponent());
            }
            
            FileOutputStream fosPublicKey = new FileOutputStream(publicKeyFile);
            BufferedOutputStream bosPublicKey = new BufferedOutputStream(fosPublicKey);
            try (ObjectOutputStream outputFilePublicKey = new ObjectOutputStream(bosPublicKey)) {
                outputFilePublicKey.writeObject(rsaPublicKey.getModulus());
                outputFilePublicKey.writeObject(rsaPublicKey.getPublicExponent());
            }
        }
    }
}
