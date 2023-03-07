/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import fr.jl.cipher.controllers.common.Utils;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Crypting class
 */
public class Crypting {
    
    private static final String FILE_CRYPTING = "file to crypting";
    private static final String KEY = "key for crypting";
    private static final String MANDATORY_ALGORITHM = "algorithm";
    private static final String ALGORITHM_NOT_SUPPORTED = "Algorithm is not supported !";
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    
    private Crypting() {
        throw new IllegalStateException("Utility class");
    }

    
    /**
     * Encrypt a file with a key in an algorithm
     * @param algorithm algorithm for crypting
     * @param filePath path of the file to crypting
     * @param keyPath path of the key for crypting
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
    public static void encrypt(final String algorithm, final String filePath, final String keyPath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {
        Utils.checkMandatoryValue(algorithm, MANDATORY_ALGORITHM);
        Utils.checkMandatoryValue(filePath, FILE_CRYPTING);
        Utils.checkMandatoryValue(keyPath, KEY);
        
        Utils.checkExistingFile(filePath, FILE_CRYPTING);
        Utils.checkExistingFile(keyPath, KEY);
        
        final int mode = Cipher.ENCRYPT_MODE;
        crypting(mode, algorithm, new File(filePath), new File(keyPath));
    }
    
    /**
     * Decrypt a file with a key in an algorithm
     * @param algorithm algorithm for crypting
     * @param filePath path of the file to crypting
     * @param keyPath path of the key for crypting
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
    public static void decrypt(final String algorithm, final String filePath, final String keyPath) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {
        Utils.checkMandatoryValue(algorithm, MANDATORY_ALGORITHM);
        Utils.checkMandatoryValue(filePath, FILE_CRYPTING);
        Utils.checkMandatoryValue(keyPath, KEY);
        
        Utils.checkExistingFile(filePath, FILE_CRYPTING);
        Utils.checkExistingFile(keyPath, KEY);
        
        final int mode = Cipher.DECRYPT_MODE;
        crypting(mode, algorithm, new File(filePath), new File(keyPath));
    }
    
    /**
     * Crypting a file with a key in an algorithm
     * @param mode encrypt or decrypt mode
     * @param algorithm algorithm for crypting
     * @param fileToCrypting the file to crypting
     * @param keyFile the key file for crypting
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
    private static void crypting(final int mode, final String algorithm, final File fileToCrypting, final File keyFile) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {
        switch (algorithm) {
            case AES:
                    AESCrypting.cryptingAES(fileToCrypting, keyFile, mode);
                break;
            case RSA:                
                    RSACrypting.cryptingRSA(fileToCrypting, keyFile, mode);
                break;
            default :
                throw new CryptingException(ALGORITHM_NOT_SUPPORTED);
        }
    }
    
}
