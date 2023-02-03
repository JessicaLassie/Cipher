/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Crypting
 */
public class Crypting {
    
    private static final String MANDATORY_FILE_CRYPTING = "File to crypting is mandatory !";
    private static final String MANDATORY_KEY = "Key is mandatory !";
    private static final String MANDATORY_ALGORITHM = "Algorithm is mandatory !";
    private static final String ALGORITHM_NOT_SUPPORTED = "Algorithm is not supported !";
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    
    /**
     * 
     * @param algorithm
     * @param filePath
     * @param keyPath
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws CryptingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     * @throws ClassNotFoundException 
     */
    public static void encrypt(String algorithm, String filePath, String keyPath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {
        Objects.requireNonNull(algorithm, MANDATORY_ALGORITHM);
        Objects.requireNonNull(filePath, MANDATORY_FILE_CRYPTING);
        Objects.requireNonNull(keyPath, MANDATORY_KEY);
        
        int mode = Cipher.ENCRYPT_MODE;
        crypting(mode, algorithm, filePath, keyPath);
    }
    
    /**
     * 
     * @param algorithm
     * @param filePath
     * @param keyPath
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws CryptingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     * @throws ClassNotFoundException 
     */
    public static void decrypt(String algorithm, String filePath, String keyPath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {
        Objects.requireNonNull(algorithm, MANDATORY_ALGORITHM);
        Objects.requireNonNull(filePath, MANDATORY_FILE_CRYPTING);
        Objects.requireNonNull(keyPath, MANDATORY_KEY);
        
        int mode = Cipher.DECRYPT_MODE;
        crypting(mode, algorithm, filePath, keyPath);
    }
    
    /**
     * 
     * @param mode
     * @param algorithm
     * @param filePath
     * @param keyPath
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws CryptingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     * @throws ClassNotFoundException 
     */
    private static void crypting(int mode, String algorithm, String filePath, String keyPath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {
        switch (algorithm) {
            case AES:
                    AESCrypting.cryptingAES(filePath, keyPath, mode);
                break;
            case RSA:                
                    RSACrypting.cryptingRSA(filePath, keyPath, mode);
                break;
            default :
                throw new CryptingException(ALGORITHM_NOT_SUPPORTED);
        }
    }
}
