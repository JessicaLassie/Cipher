/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.CryptingException;
import fr.jl.cipher.controller.EncryptionController;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
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
abstract class AbstractEncryptionController {
    
    private static final String PATH = "test\\fr\\jl\\cipher\\resources";
    private static final String FILE_TO_ENCRYPT = "doc.txt";
    private static final String KEY_TO_AES_ENCRYPT = "AES_key.txt";
    private static final String EMPTY_KEY = "empty_key.txt";
    private static final String WRONG_KEY = "wrong_key.txt";
    private static final String RSA_PUBLIC_KEY = "RSA_public_key.txt";
    private static final String RSA_PRIVATE_KEY = "RSA_private_key.txt";
    private static final String DOC_ENCRYPTED = "doc_encrypted";
    private static final String DECRYPTED = "decrypted";
    private static final String FILE_PATH = PATH + "\\" + FILE_TO_ENCRYPT;
    private static final String AES_KEY_PATH = PATH + "\\" + KEY_TO_AES_ENCRYPT;
    private static final String EMPTY_KEY_PATH = PATH + "\\" + EMPTY_KEY;
    private static final String WRONG_KEY_PATH = PATH + "\\" + WRONG_KEY;
    private static final String RSA_PUBLIC_KEY_PATH = PATH + "\\" + RSA_PUBLIC_KEY;
    private static final String RSA_PRIVATE_KEY_PATH = PATH + "\\" + RSA_PRIVATE_KEY;
    
    protected void verifySuccessfullEncryptAES() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
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
    
    protected void verifyErrorEncryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.encryptAES(FILE_PATH, null);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.encryptAES(FILE_PATH, EMPTY_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.encryptAES(FILE_PATH, WRONG_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.encryptAES(FILE_PATH, "notExistingKey.txt");
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.encryptAES(null, AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorEncryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.encryptAES("notExistingFile.txt", AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifySuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
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
    
    protected void verifyErrorDecryptAESWithNullKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), null);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithEmptyKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), EMPTY_KEY_PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithWrongKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), WRONG_KEY_PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        //Encrypt
        EncryptionController.encryptAES(FILE_PATH, AES_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptAES(PATH + "\\" + filesEncrypted[0].getName(), "notExistingKey.txt");
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.decryptAES(null, AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifyErrorDecryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        EncryptionController.decryptAES("notExistingFile.txt", AES_KEY_PATH);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(0, files.length);
    }
    
    protected void verifySuccessfullEncryptRSA() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidAlgorithmParameterException {
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
    
    protected void verifySuccessfullDecryptRSA() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        //Encrypt
        EncryptionController.encryptRSA(FILE_PATH, RSA_PUBLIC_KEY_PATH);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        EncryptionController.decryptRSA(PATH + "\\" + filesEncrypted[0].getName(), RSA_PRIVATE_KEY_PATH);
        File[] filesDecrypted = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(1, filesDecrypted.length);
        for(File file : filesDecrypted) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
}
