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
    
    private RSACrypting() {
        throw new IllegalStateException("Utility class");
    }
    
    /**
     * Crypting a file in RSA
     * @param fileToCrypting the file to crypting
     * @param keyFile the key file for crypting
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
    protected static void cryptingRSA(final File fileToCrypting, final File keyFile, final int mode) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        Key key;
        if (mode == 1) {
            key = getRSAPublicKey(keyFile);
        } else {
            key = getRSAPrivateKey(keyFile);
        } 

        File outputFile = CryptingUtils.preFormating(mode, fileToCrypting);  
        
        if (key != null) {
            crypting(mode, key, fileToCrypting, outputFile, RSA);
        } else {
            throw new CryptingException(EMPTY_KEY);
        }                   
    }
    
    /**
     * Get private key for decrypt in RSA
     * @param keyFile private key file
     * @return private key
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private static PrivateKey getRSAPrivateKey(final File keyFile) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        BufferedInputStream bis;
        ObjectInputStream ois;
        PrivateKey privateKey;
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            bis = new BufferedInputStream(fis);
            ois = new ObjectInputStream(bis);
            BigInteger modulo = (BigInteger) ois.readObject();
            BigInteger exposant = (BigInteger) ois.readObject();
            RSAPrivateKeySpec specification = new RSAPrivateKeySpec(modulo, exposant);
            KeyFactory factory = KeyFactory.getInstance(RSA);
            privateKey = factory.generatePrivate(specification);
        }
        bis.close();
        ois.close();
        return privateKey;
    }
    
    /**
     * Get public key for encrypt in RSA
     * @param keyFile public key file
     * @return public key
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private static PublicKey getRSAPublicKey(final File keyFile) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        BufferedInputStream bis;
        ObjectInputStream ois;
        PublicKey publicKey;
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            bis = new BufferedInputStream(fis);
            ois = new ObjectInputStream(bis);
            BigInteger modulo = (BigInteger) ois.readObject();
            BigInteger exposant = (BigInteger) ois.readObject();
            RSAPublicKeySpec specification = new RSAPublicKeySpec(modulo, exposant);
            KeyFactory factory = KeyFactory.getInstance(RSA);
            publicKey = factory.generatePublic(specification);
        }
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
     */    
    protected static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        try (FileOutputStream outputStream = new FileOutputStream(outputFile);FileInputStream inputStream = new FileInputStream(inputFile)) {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key);
            byte[] inputBytes = new byte[inputStream.available()];
            while (inputStream.read(inputBytes) > -1) {
                byte[] outputBytes = cipher.doFinal(inputBytes);           
                outputStream.write(outputBytes);
            }
        }
    }
}
