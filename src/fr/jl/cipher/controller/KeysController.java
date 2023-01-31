/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Writer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 */
public class KeysController {
    
    private static final String MANDATORY_OUTPUT_FOLDER = "Output folder is mandatory !";
    private static final String KEY = "\\key_";
    private static final String PUBLIC_KEY = "\\public_key_";
    private static final String PRIVATE_KEY = "\\private_key_";
    private static final String TXT_EXTENSION = ".txt";
    
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String DATE_FORMAT = "yyyyMMddHHmmss";
    
    /**
     * Generate and save the AES key
     * @param outputPath the path for save the AES key
     * @throws NoSuchAlgorithmException
     * @throws IOException 
     */
    public static void generateAndSaveAESKey(String outputPath) throws NoSuchAlgorithmException, IOException{
        Objects.requireNonNull(outputPath, MANDATORY_OUTPUT_FOLDER);
        SecretKey key = generateAESKey();
        saveAESKey(key, outputPath);
    }
    
    /**
     * Generate and save the RSA keys
     * @param outputPath the path for save the RSA keys
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException 
     */
    public static void generateAndSaveRSAKeys(String outputPath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Objects.requireNonNull(outputPath, MANDATORY_OUTPUT_FOLDER);
        
        KeyPair keyPair = generateRSAKeyPair();
        saveRSAKeyPair(keyPair, outputPath);
    }
    
    /**
     * Generate key in 128 bits for AES encryption
     * @return key in 128 bits
     * @throws NoSuchAlgorithmException 
     */
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }
    
    /**
     * Save key in a text file
     * @param key key in 128 bits
     * @param keyFilePath path for save the key file
     * @throws IOException
     */
    private static void saveAESKey(final SecretKey key, final String keyFilePath) throws IOException {
        SimpleDateFormat formater = new SimpleDateFormat(DATE_FORMAT);
        final String date = formater.format(new Date());
        File keyFile = new File(keyFilePath + KEY + date + TXT_EXTENSION);
        try (Writer fw = new FileWriter(keyFile.getAbsoluteFile())) {
            byte encoded[] = key.getEncoded();
            final String encodedKey = Base64.getEncoder().encodeToString(encoded);
            fw.write(encodedKey);
        }            
    }
    
    /**
     * Generate key pair for RSA crypting
     * @return keys pair (private key and public key)
     * @throws NoSuchAlgorithmException
     */
    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(RSA);
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();           
        return keyPair;
    }
    
    /**
     * Save private key in a text file
     * @param keyPair
     * @param keysFilesPath
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
            ObjectOutputStream outputFilePrivateKey = new ObjectOutputStream(bosPrivateKey);
            outputFilePrivateKey.writeObject(rsaPrivateKey.getModulus());
            outputFilePrivateKey.writeObject(rsaPrivateKey.getPrivateExponent());
            outputFilePrivateKey.close();
            
            FileOutputStream fosPublicKey = new FileOutputStream(publicKeyFile);
            BufferedOutputStream bosPublicKey = new BufferedOutputStream(fosPublicKey);
            ObjectOutputStream outputFilePublicKey = new ObjectOutputStream(bosPublicKey);
            outputFilePublicKey.writeObject(rsaPublicKey.getModulus());
            outputFilePublicKey.writeObject(rsaPublicKey.getPublicExponent());
            outputFilePublicKey.close();
        }
    }
}
