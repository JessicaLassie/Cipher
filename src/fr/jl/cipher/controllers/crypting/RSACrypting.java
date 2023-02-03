/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA Crypting
 */
public class RSACrypting {
    
    private static final String RSA = "RSA";
    private static final String EMPTY_KEY = "Key is empty !";
    
    /**
     * Crypting a file in RSA
     * @param filePath path of the file to crypting
     * @param keyFilePath path of the key for crypting
     * @param mode encrypt or decrypt mode
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     * @throws ClassNotFoundException 
     * @throws InvalidAlgorithmParameterException 
     */
    protected static void cryptingRSA(final String filePath, final String keyFilePath, final int mode) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        Key key = null;
        switch (mode) {
            case 1:
                key = getRSAPublicKey(keyFilePath);
                break;
            case 2:
                key = getRSAPrivateKey(keyFilePath);
                break;
        } 

        File inputFile = new File(filePath);
        File outputFile = CryptingUtils.preFormating(mode, filePath);  
        
        if (key != null) {
            crypting(mode, key, inputFile, outputFile, RSA);
        } else {
            throw new CryptingException(EMPTY_KEY);
        }                   
    }
    
    /**
     * Get private key for decrypt in RSA
     * @param keyFilePath private key file path
     * @return private key
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private static PrivateKey getRSAPrivateKey(final String keyFilePath) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(keyFilePath);
        BufferedInputStream bis = new BufferedInputStream(fis);       
        ObjectInputStream ois = new ObjectInputStream(bis);
        BigInteger modulo = (BigInteger) ois.readObject();
        BigInteger exposant = (BigInteger) ois.readObject();
        RSAPrivateKeySpec specification = new RSAPrivateKeySpec(modulo, exposant);
        KeyFactory factory = KeyFactory.getInstance(RSA);
        PrivateKey privateKey = factory.generatePrivate(specification);
        fis.close();
        bis.close();
        ois.close();
        return privateKey;
    }
    
    /**
     * Get public key for encrypt in RSA
     * @param keyFilePath public key file path
     * @return public key
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private static PublicKey getRSAPublicKey(final String keyFilePath) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(keyFilePath);
        BufferedInputStream bis = new BufferedInputStream(fis);       
        ObjectInputStream ois = new ObjectInputStream(bis);
        BigInteger modulo = (BigInteger) ois.readObject();
        BigInteger exposant = (BigInteger) ois.readObject();
        RSAPublicKeySpec specification = new RSAPublicKeySpec(modulo, exposant);
        KeyFactory factory = KeyFactory.getInstance(RSA);
        PublicKey publicKey = factory.generatePublic(specification);
        fis.close();
        bis.close();
        ois.close();
        return publicKey;
    }
    
    /**
     * Encrypt or decrypt a file
     * @param mode encrypt or decrypt mode
     * @param key key for encrypt or decrypt
     * @param inputFile file to encrypt or decrypt
     * @param outputFile encrypted file or decrypted file
     * @param algorithm algorithm of crypting
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws InvalidAlgorithmParameterException 
     */    
    protected static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        FileInputStream inputStream = new FileInputStream(inputFile); 
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(mode, key);
        byte[] inputBytes = new byte[inputStream.available()];
        while (inputStream.read(inputBytes) > -1) {
            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);           
        }
        inputStream.close();
        outputStream.close();
    }
}
