/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 */
public class EncryptionController {
    
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String DATE_FORMAT = "yyyyMMddHHmmss";

    private static final String MANDATORY_MODE = "Mode is mandatory !";
    private static final String MANDATORY_FILE_ENCRYPT = "File to encrypt is mandatory !";
    private static final String MANDATORY_FILE_DECRYPT = "File to decrypt is mandatory !";
    private static final String MANDATORY_KEY = "Key is mandatory !";
    private static final String EMPTY_KEY = "Key is empty !";
    
    /**
     * Encrypt a file in AES
     * @param mode encrypt or decrypt mode
     * @param filePath path of the file to encrypt
     * @param keyFilePath path of the key for encrypt
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     */
    public static void encryptAES(final int mode, final String filePath, final String keyFilePath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        Objects.requireNonNull(mode, MANDATORY_MODE);
        Objects.requireNonNull(filePath, MANDATORY_FILE_ENCRYPT);
        Objects.requireNonNull(keyFilePath, MANDATORY_KEY);
        
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);
        
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
                    crypting(mode, key, inputFile, outputFile, AES);
                } else {
                    throw new CryptingException(EMPTY_KEY);
                }
            }
        } else {
            throw new CryptingException(MANDATORY_KEY);             
        }
                   
    }
    
    /**
     * Decrypt a file in AES
     * @param mode encrypt or decrypt mode
     * @param filePath path of the file to decrypt
     * @param keyFilePath path of the key for decrypt
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     */
    public static void decryptAES(final int mode, final String filePath, final String keyFilePath) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        Objects.requireNonNull(mode, MANDATORY_MODE);
        Objects.requireNonNull(filePath, MANDATORY_FILE_DECRYPT);
        Objects.requireNonNull(keyFilePath, MANDATORY_KEY);
        
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);
        if(!keyFilePath.equals("")) {
            try (BufferedReader reader = new BufferedReader(new FileReader(keyFilePath))) {
                String line;
                String contentFile = "";
                while ((line = reader.readLine()) != null) {
                    contentFile = line;
                }
                byte[] decodedKey = Base64.getDecoder().decode(contentFile);
                if(decodedKey.length > 0) {
                    SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, AES);
                    crypting(mode, key, inputFile, outputFile, AES);
                } else {
                    throw new CryptingException(EMPTY_KEY);
                }
            }
        } else {
            throw new CryptingException(MANDATORY_KEY);
        }
        
    }
    
    /**
     * Encrypt a file in RSA
     * @param mode encrypt or decrypt mode
     * @param filePath path of the file to encrypt
     * @param keyFilePath path of the key for encrypt
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     * @throws ClassNotFoundException 
     */
    public static void encryptRSA(final int mode, final String filePath, final String keyFilePath) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException {
        Objects.requireNonNull(mode, MANDATORY_MODE);
        Objects.requireNonNull(filePath, MANDATORY_FILE_ENCRYPT);
        Objects.requireNonNull(keyFilePath, MANDATORY_KEY);
        
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);  
        
        if(!keyFilePath.equals("")){
            PublicKey publicKey = getRSAPublicKey(keyFilePath);
            if (publicKey != null) {
                crypting(mode, publicKey, inputFile, outputFile, RSA);
            } else {
                throw new CryptingException(EMPTY_KEY);
            }                   
        } else {
            throw new CryptingException(MANDATORY_KEY);  
        }
    }
    
    /**
     * Decrypt a file in RSA
     * @param mode encrypt or decrypt mode
     * @param filePath path of the file to decrypt
     * @param keyFilePath path of the key for decrypt
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static void decryptRSA(final int mode, final String filePath, final String keyFilePath) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        Objects.requireNonNull(mode, MANDATORY_MODE);
        Objects.requireNonNull(filePath, MANDATORY_FILE_DECRYPT);
        Objects.requireNonNull(keyFilePath, MANDATORY_KEY);
        
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);
        
        if(!keyFilePath.equals("")){
            PrivateKey privateKey = getRSAPrivateKey(keyFilePath);
            if (privateKey != null) {
                crypting(mode, privateKey, inputFile, outputFile, RSA);
            } else {
                throw new CryptingException(EMPTY_KEY);
            }                   
        } else {
            throw new CryptingException(MANDATORY_KEY);  
        }
    }
    
    /**
     * Create format file
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @return file for encrypt or decrypt output
     */
    private static File preFormating(final int mode, final String filePath) {
        SimpleDateFormat formater = new SimpleDateFormat(DATE_FORMAT);
        final String date = formater.format(new Date());
        final int pos = filePath.indexOf('.');
        String modeType = "";
        switch (mode) {
            case 1:
                modeType = "_encrypted_";
                break;
            case 2:
                modeType = "_decrypted_";
                break;
            default :
                break;
        }
        return new File(filePath.substring(0, pos) + modeType + date + filePath.substring(pos, filePath.length()));
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
     */    
    private static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
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
