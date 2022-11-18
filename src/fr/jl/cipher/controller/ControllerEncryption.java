/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Jessica LASSIE
 */
public class ControllerEncryption {
    
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String DATE_FORMAT = "yyyyMMddHHmmss";
    private static final String KEY = "\\key_";
    private static final String PUBLIC_KEY = "\\public_key_";
    private static final String PRIVATE_KEY = "\\private_key_";
    private static final String TXT_EXTENSION = ".txt";
    
    private ControllerEncryption() { 
    };
    
    /**
     * Encrypt a file in AES
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param keyFilePath path of key
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     */
    public static void encryptAES(final int mode, final String filePath, final String keyFilePath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);
        
        if(!keyFilePath.equals("")){
            // If we have a key for encrypt
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
                    throw new CryptingException("Key is empty !");
                }
            }
        } else {
            // If we DON'T have a key for encrypt
            // Generate a key
            SecretKey key = generateAESKey();
            File keyFile = saveAESKey(key, outputFile.getParent());
            if (key != null && keyFile.exists()){
                crypting(mode, key, inputFile, outputFile, AES);
            }
        }
                   
    }
    
    /**
     * Decrypt a file in AES
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param keyFilePath path for save the key file
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     */
    public static void decryptAES(final int mode, final String filePath, final String keyFilePath) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);
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
                //remonter une erreur clé vide
                throw new CryptingException("Key is empty !");
            }
        }
    }
    
    /**
     * Encrypt a file in RSA
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param keyFilePath path of key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     * @throws CryptingException 
     */
    public static void encryptRSA(final int mode, final String filePath, final String keyFilePath) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException {
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);  
        
        if(!keyFilePath.equals("")){
            // If we have a key for encrypt
            PublicKey publicKey = getRSAPublicKey(keyFilePath);
            if (publicKey != null) {
                crypting(mode, publicKey, inputFile, outputFile, RSA);
            } else {
                //remonter une erreur clé vide
                throw new CryptingException("Key is empty !");
            }                   
        } else {
            // If we DON'T have a key for encrypt
            // Generate the keys
            KeyPair keyPair = generateRSAKeyPair();
            ArrayList<File> keysFiles = saveRSAKeyPair(keyPair, outputFile.getParent());
            if (keysFiles.size() == 2){
                crypting(mode, keyPair.getPublic(), inputFile, outputFile, RSA);
            }  
        }
    }
    
    /**
     * Decrypt a file in RSA
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param keyFilePath path for save the key file
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static void decryptRSA(final int mode, final String filePath, final String keyFilePath) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        File inputFile = new File(filePath);
        File outputFile = preFormating(mode, filePath);
        PrivateKey privateKey = getRSAPrivateKey(keyFilePath);
        if (privateKey != null) {
            crypting(mode, privateKey, inputFile, outputFile, RSA);
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
     * @param key in 128 bits
     * @param keyFilePath path for save the key file
     * @return file with key
     * @throws IOException
     */
    private static File saveAESKey(final SecretKey key, final String keyFilePath) throws IOException {
        SimpleDateFormat formater = new SimpleDateFormat(DATE_FORMAT);
        final String date = formater.format(new Date());
        File keyFile = new File(keyFilePath + KEY + date + TXT_EXTENSION);
        try (Writer fw = new FileWriter(keyFile.getAbsoluteFile())) {
            byte encoded[] = key.getEncoded();
            final String encodedKey = Base64.getEncoder().encodeToString(encoded);
            fw.write(encodedKey);
        }            
        return keyFile;
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
     * @return file with private key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException 
     * @throws IOException
     */
    private static ArrayList<File> saveRSAKeyPair(final KeyPair keyPair, final String keysFilesPath) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        ArrayList<File> keysFiles = new ArrayList<>();
        
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
        
        keysFiles.add(privateKeyFile);
        keysFiles.add(publicKeyFile);
        return keysFiles;
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
     * @param algorithm of crypting
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
