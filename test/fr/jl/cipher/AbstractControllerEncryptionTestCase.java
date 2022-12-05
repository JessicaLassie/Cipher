/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.EncryptionController;
import fr.jl.cipher.controller.CryptingException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 *
 */
abstract class AbstractControllerEncryptionTestCase {
    
    private final static int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
    private final static int DECRYPT_MODE = Cipher.DECRYPT_MODE;
    private final static String PATH = "test\\fr\\jl\\cipher\\resources";
    private final static String FILE_TO_ENCRYPT = "doc.txt";
    private final static String KEY_TO_AES_ENCRYPT = "AES_key.txt";
    private final static String EMPTY_KEY = "empty_key.txt";
    private final static String KEY_TO_RSA_ENCRYPT = "RSA_key.txt";
    private final static String FILE_PATH = PATH + "\\" + FILE_TO_ENCRYPT;
    private final static String AES_KEY_PATH = PATH + "\\" + KEY_TO_AES_ENCRYPT;
    private final static String EMPTY_KEY_PATH = PATH + "\\" + EMPTY_KEY;
    private final static String DOC_ENCRYPTED = "doc_encrypted";
    private final static String DECRYPTED = "decrypted";
    private final static String KEY = "key";
    private static final String PUBLIC_KEY = "public_key_";
    private static final String PRIVATE_KEY = "private_key_";
    private final static String RSA_PUBLIC_KEY_PATH = PATH + "\\" + KEY_TO_RSA_ENCRYPT;
    
    protected void verifySuccessfullEncryptAESWithoutKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, "");
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.startsWith(KEY));
        assertEquals(2, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifySuccessfullEncryptAESWithKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(1, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifySuccessfullEncryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, null);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.startsWith(KEY));
        assertEquals(2, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifyErrorEncryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, EMPTY_KEY_PATH);
    }
    
    protected void verifySuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, "");
        //Decrypt
        File dir = new File(PATH);
        File[] filesKey = dir.listFiles((dir1, name) -> name.startsWith(KEY));
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(DECRYPT_MODE, PATH + "\\" + filesEncrypted[0].getName(), PATH + "\\" + filesKey[0].getName());
        File[] filesDecrypted = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(1, filesDecrypted.length);
        for(File file : filesDecrypted) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifyErrorDecryptAESWithNullKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, "");
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(DECRYPT_MODE, PATH + "\\" + filesEncrypted[0].getName(), null);
    }
    
    protected void verifyErrorDecryptAESWithEmptyFileKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, "");
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(DECRYPT_MODE, PATH + "\\" + filesEncrypted[0].getName(), "");
    }
    
    protected void verifyErrorDecryptAESWithEmptyKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(ENCRYPT_MODE, FILE_PATH, "");
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(DECRYPT_MODE, PATH + "\\" + filesEncrypted[0].getName(), EMPTY_KEY_PATH);
    }
    
    protected void verifySuccessfullEncryptRSAWithoutKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException {
        EncryptionController.encryptRSA(ENCRYPT_MODE, FILE_PATH, "");
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.startsWith(PUBLIC_KEY) || name.startsWith(PRIVATE_KEY));
        assertEquals(3, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifySuccessfullEncryptRSAWithKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException {
        EncryptionController.encryptRSA(ENCRYPT_MODE, FILE_PATH, RSA_PUBLIC_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(1, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifySuccessfullDecryptRSA() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptRSA(ENCRYPT_MODE, FILE_PATH, "");
        //Decrypt
        File dir = new File(PATH);
        File[] filesKey = dir.listFiles((dir1, name) -> name.startsWith(PRIVATE_KEY));
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptRSA(DECRYPT_MODE, PATH + "\\" + filesEncrypted[0].getName(), PATH + "\\" + filesKey[0].getName());
        File[] filesDecrypted = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(1, filesDecrypted.length);
        for(File file : filesDecrypted) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
}
