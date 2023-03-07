/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
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
    private static final String EMPTY_KEY = "Key is empty !";
    
    private AESCrypting() {
        throw new IllegalStateException("Utility class");
    }
    
    /**
     * Crypting a file in AES 256 bits
     * @param fileToCrypting the file to crypting
     * @param keyFile the key file for crypting
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
    protected static void cryptingAES(final File fileToCrypting, final File keyFile, final int mode) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {              
 
        File outputFile = CryptingUtils.preFormating(mode, fileToCrypting);
        
        try (BufferedReader reader = new BufferedReader(new FileReader(keyFile))) {
            String line;
            String contentFile = "";
            while ((line = reader.readLine()) != null) {
                contentFile = line;
            }
            byte[] encodedKey = Base64.getDecoder().decode(contentFile);                
            if(encodedKey.length > 0) {
                SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, AES);
                IvParameterSpec parameterSpec = new IvParameterSpec(new byte[16]);
                crypting(mode, key, fileToCrypting, outputFile, AES_CBC_PKCS5PADDING, parameterSpec);
            } else {
                throw new CryptingException(EMPTY_KEY);
            }
        }                  
    }
    
    /**
     * Encrypt or decrypt a file
     * @param mode encrypt or decrypt mode
     * @param key key for encrypt or decrypt
     * @param inputFile file to encrypt or decrypt
     * @param outputFile encrypted file or decrypted file
     * @param algorithm algorithm of crypting
     * @param parameterSpec IV parameter
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws InvalidAlgorithmParameterException 
     */    
    private static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm, final IvParameterSpec parameterSpec) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        try (FileOutputStream outputStream = new FileOutputStream(outputFile);FileInputStream inputStream = new FileInputStream(inputFile)) {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key, parameterSpec);
            byte[] inputBytes = new byte[inputStream.available()];
            while (inputStream.read(inputBytes) > -1) {
                byte[] outputBytes = cipher.doFinal(inputBytes);           
                outputStream.write(outputBytes);
            }
        }
    }
}
