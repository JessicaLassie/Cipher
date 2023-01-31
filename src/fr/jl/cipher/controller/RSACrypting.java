/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA Crypting
 */
public class RSACrypting {
    
    private static final String RSA = "RSA";
    private static final String MANDATORY_FILE_CRYPTING = "File to crypting is mandatory !";
    private static final String MANDATORY_KEY = "Key is mandatory !";
    private static final String MANDATORY_MODE = "Mode is mandatory !";
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
    public static void cryptingRSA(final String filePath, final String keyFilePath, final String mode) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        Objects.requireNonNull(filePath, MANDATORY_FILE_CRYPTING);
        Objects.requireNonNull(keyFilePath, MANDATORY_KEY);
        Objects.requireNonNull(mode, MANDATORY_MODE);

        int cryptingMode = Cipher.ENCRYPT_MODE;
        Key key = null;
        if(mode.toLowerCase().equals("decrypt")){
            cryptingMode = Cipher.DECRYPT_MODE;
            key = getRSAPrivateKey(keyFilePath);
        } else {
            key = getRSAPublicKey(keyFilePath);
        }     

        File inputFile = new File(filePath);
        File outputFile = CryptingUtils.preFormating(cryptingMode, filePath);  
        
        if(!keyFilePath.equals("")){
            if (key != null) {
                Crypting.crypting(cryptingMode, key, inputFile, outputFile, RSA);
            } else {
                throw new CryptingException(EMPTY_KEY);
            }                   
        } else {
            throw new CryptingException(MANDATORY_KEY);  
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
    
}
