/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Crypting
 */
public class Crypting {
    
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
    protected static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm, final IvParameterSpec... parameterSpec) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        FileInputStream inputStream = new FileInputStream(inputFile); 
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        Cipher cipher = Cipher.getInstance(algorithm);
        if(parameterSpec.length != 0) {
            cipher.init(mode, key, parameterSpec[0]);
        } else {
            cipher.init(mode, key);
        }
        byte[] inputBytes = new byte[inputStream.available()];
        while (inputStream.read(inputBytes) > -1) {
            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);           
        }
        inputStream.close();
        outputStream.close();
    }
}
