/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES Crypting
 */
public class AESCrypting {
    
    private static final String AES = "AES";
    private static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
    private static final String MANDATORY_FILE_CRYPTING = "File to crypting is mandatory !";
    private static final String MANDATORY_KEY = "Key is mandatory !";
    private static final String MANDATORY_MODE = "Mode is mandatory !";
    private static final String EMPTY_KEY = "Key is empty !";
    
    /**
     * Crypting a file in AES 256 bits
     * @param filePath path of the file to crypting
     * @param keyFilePath path of the key for crypting
     * @param mode encrypt or decrypt mode
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     * @throws InvalidAlgorithmParameterException 
     */
    public static void cryptingAES(final String filePath, final String keyFilePath, final String mode) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        Objects.requireNonNull(filePath, MANDATORY_FILE_CRYPTING);
        Objects.requireNonNull(keyFilePath, MANDATORY_KEY);
        Objects.requireNonNull(mode, MANDATORY_MODE);

        int cryptingMode = Cipher.ENCRYPT_MODE;       
        if(mode.toLowerCase().equals("decrypt")){
            cryptingMode = Cipher.DECRYPT_MODE;
        }
               
        File inputFile = new File(filePath);
        File outputFile = CryptingUtils.preFormating(cryptingMode, filePath);
        
        if(!keyFilePath.equals("")){
            try (BufferedReader reader = new BufferedReader(new FileReader(keyFilePath))) {
                String line;
                String contentFile = "";
                while ((line = reader.readLine()) != null) {
                    contentFile = line;
                }
                byte[] encodedKey = Base64.getDecoder().decode(contentFile);                
                if(encodedKey.length > 0) {
                    SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, AES);
                    IvParameterSpec parameterSpec = new IvParameterSpec(new byte[16]);
                    Crypting.crypting(cryptingMode, key, inputFile, outputFile, AES_CBC_PKCS5PADDING, parameterSpec);
                } else {
                    throw new CryptingException(EMPTY_KEY);
                }
            }
        } else {
            throw new CryptingException(MANDATORY_KEY);             
        }                   
    }
    
}
