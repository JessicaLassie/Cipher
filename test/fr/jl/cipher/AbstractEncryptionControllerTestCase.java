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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 *
 */
abstract class AbstractEncryptionControllerTestCase {
    
    private final static String PATH = "test\\fr\\jl\\cipher\\resources";
    private final static String FILE_TO_ENCRYPT = "doc.txt";
    private final static String KEY_TO_AES_ENCRYPT = "AES_key.txt";
    private final static String EMPTY_KEY = "empty_key.txt";
    private final static String WRONG_KEY = "wrong_key.txt";
    private final static String KEY_TO_RSA_ENCRYPT = "RSA_key.txt";
    private final static String FILE_PATH = PATH + "\\" + FILE_TO_ENCRYPT;
    private final static String AES_KEY_PATH = PATH + "\\" + KEY_TO_AES_ENCRYPT;
    private final static String EMPTY_KEY_PATH = PATH + "\\" + EMPTY_KEY;
    private final static String WRONG_KEY_PATH = PATH + "\\" + WRONG_KEY;
    private final static String DOC_ENCRYPTED = "doc_encrypted";
    private final static String DECRYPTED = "decrypted";
    private final static String KEY = "key";
    private final static String PUBLIC_KEY = "public_key_";
    private final static String PRIVATE_KEY = "private_key_";
    private final static String RSA_PUBLIC_KEY_PATH = PATH + "\\" + KEY_TO_RSA_ENCRYPT;
    
    protected void verifySuccessfullEncryptAES() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(1, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifyErrorEncryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(FILE_PATH, null);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(FILE_PATH, EMPTY_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(FILE_PATH, WRONG_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(FILE_PATH, "notExistingKey.txt");
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES(null, AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.encryptAES("notExistingFile.txt", AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifySuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), AES_KEY_PATH);
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
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), null);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithEmptyKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), EMPTY_KEY_PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithWrongKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), WRONG_KEY_PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), "notExistingKey.txt");
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.decryptAES(null, AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException {
        EncryptionController.decryptAES("notExistingFile.txt", AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifySuccessfullEncryptRSAWithoutKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException {
        EncryptionController.encryptRSA(FILE_PATH, "");
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
        EncryptionController.encryptRSA(FILE_PATH, RSA_PUBLIC_KEY_PATH);
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
        EncryptionController.encryptRSA(FILE_PATH, "");
        //Decrypt
        File dir = new File(PATH);
        File[] filesKey = dir.listFiles((dir1, name) -> name.startsWith(PRIVATE_KEY));
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptRSA(PATH + "\\" + filesEncrypted[0].getName(), PATH + "\\" + filesKey[0].getName());
        File[] filesDecrypted = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(1, filesDecrypted.length);
        for(File file : filesDecrypted) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
}
