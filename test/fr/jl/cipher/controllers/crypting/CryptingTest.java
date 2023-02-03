/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.After;
import org.junit.Test;

/**
 * Tests for AESEncryption
 */
public class CryptingTest extends AbstractCrypting {
       
    private static final String PATH = "test\\fr\\jl\\cipher\\resources";    
    private static final String DOC_ENCRYPTED = "doc_encrypted";
    private static final String DECRYPTED = "decrypted";
    private static final String FILE_TO_ENCRYPT = "doc.txt";
    private static final String FILE_TO_DECRYPT = "doc_for_decrypt.txt";
    private static final String FILE_TO_DECRYPT_IN_RSA = "doc_for_decrypt_in_RSA.txt";
    private static final String KEY_TO_AES_ENCRYPT = "AES_key.txt";
    private static final String FILE_PATH = PATH + "\\" + FILE_TO_ENCRYPT;
    private static final String FILE_PATH_TO_DECRYPT = PATH + "\\" + FILE_TO_DECRYPT;
    private static final String FILE_PATH_TO_DECRYPT_IN_RSA = PATH + "\\" + FILE_TO_DECRYPT_IN_RSA;
    private static final String AES_KEY_PATH = PATH + "\\" + KEY_TO_AES_ENCRYPT;
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String EMPTY_KEY = "empty_key.txt";
    private static final String WRONG_KEY = "wrong_key.txt";
    private static final String EMPTY_KEY_PATH = PATH + "\\" + EMPTY_KEY;
    private static final String WRONG_KEY_PATH = PATH + "\\" + WRONG_KEY;
    private static final String RSA_PUBLIC_KEY = "RSA_public_key.txt";
    private static final String RSA_PUBLIC_KEY_PATH = PATH + "\\" + RSA_PUBLIC_KEY;
    private static final String RSA_PRIVATE_KEY = "RSA_private_key.txt";
    private static final String RSA_PRIVATE_KEY_PATH = PATH + "\\" + RSA_PRIVATE_KEY;
    
    @After
    public void tearDown() {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.contains(DECRYPTED));
        for(File file : files) {
            file.delete();
        }
    }
    
    @Test
    public void testSuccessfullEncryptAES() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, FILE_PATH, AES_KEY_PATH);
        verifyEncryptedDocExist();
    }
    
    @Test
    public void testSuccessfullEncryptRSA() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(RSA, FILE_PATH, RSA_PUBLIC_KEY_PATH);
        verifyEncryptedDocExist();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptWithNullAlgorithm() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ClassNotFoundException{        
        Crypting.encrypt(null, FILE_PATH, AES_KEY_PATH);
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorEncryptWithNotExistingAlgorithm() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {        
        Crypting.encrypt("notExistingAlgorithm", FILE_PATH, AES_KEY_PATH);
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, FILE_PATH, null);
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorEncryptWithEmptyKeyPath() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, FILE_PATH, "");
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorEncryptWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, FILE_PATH, EMPTY_KEY_PATH);
    }
    
    @Test
    (expected=IllegalArgumentException.class)
    public void testErrorEncryptWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, FILE_PATH, WRONG_KEY_PATH);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorEncryptWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeySpecException{        
        Crypting.encrypt(AES, FILE_PATH, "notExistingKey.txt");
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, null, AES_KEY_PATH);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorEncryptWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.encrypt(AES, "notExistingFile.txt", AES_KEY_PATH);
    }
    
    @Test
    public void testSuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{
        Crypting.decrypt(AES, FILE_PATH_TO_DECRYPT, AES_KEY_PATH);
        verifyDecryptedDocExist();
    }
    
    @Test
    public void testSuccessfullDecryptRSA() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{
        Crypting.decrypt(RSA, FILE_PATH_TO_DECRYPT_IN_RSA, RSA_PRIVATE_KEY_PATH);
        verifyDecryptedDocExist();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException{        
        Crypting.decrypt(AES, FILE_PATH_TO_DECRYPT, null);
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptWithEmptyKeyPath() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.decrypt(AES, FILE_PATH_TO_DECRYPT, "");
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException{        
        Crypting.decrypt(AES, FILE_PATH_TO_DECRYPT, EMPTY_KEY_PATH);
    }
    
    @Test
    (expected=IllegalArgumentException.class)
    public void testErrorDecryptWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException{        
        Crypting.decrypt(AES, FILE_PATH_TO_DECRYPT, WRONG_KEY_PATH);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorDecryptWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.decrypt(AES, FILE_PATH_TO_DECRYPT, "notExistingKey.txt");
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.decrypt(AES, null, AES_KEY_PATH);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorDecryptWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException{        
        Crypting.decrypt(AES, "notExistingFile.txt", AES_KEY_PATH);
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptWithNullAlgorithm() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ClassNotFoundException{        
        Crypting.decrypt(null, FILE_PATH, AES_KEY_PATH);
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptWithNotExistingAlgorithm() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException, InvalidKeySpecException, ClassNotFoundException {        
        Crypting.decrypt("notExistingAlgorithm", FILE_PATH, AES_KEY_PATH);
    }
    
}
