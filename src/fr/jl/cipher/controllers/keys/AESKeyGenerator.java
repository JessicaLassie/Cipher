/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.keys;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * AES Key Generator
 */
public class AESKeyGenerator {
    
    private static final String KEY = "\\key_";
    private static final String AES = "AES";
    private static final String TXT_EXTENSION = ".txt";
    private static final String DATE_FORMAT = "yyyyMMddHHmmss";
    
    /**
     * Generate and save the AES key
     * @param outputPath the path for save the AES key
     * @throws NoSuchAlgorithmException
     * @throws IOException 
     */
    protected static void generateAndSaveAESKey(String outputPath) throws NoSuchAlgorithmException, IOException{
        SecretKey key = generateAESKey();
        saveAESKey(key, outputPath);
    }
    
    /**
     * Generate key in 256 bits for AES encryption
     * @return key in 256 bits
     * @throws NoSuchAlgorithmException 
     */
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(256);
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
}
