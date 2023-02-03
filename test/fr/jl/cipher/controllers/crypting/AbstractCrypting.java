/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
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
abstract class AbstractCrypting {
    
    private static final String PATH = "test\\fr\\jl\\cipher\\resources";
    private static final String FILE_TO_ENCRYPT = "doc.txt";
    private static final String RSA_PUBLIC_KEY = "RSA_public_key.txt";
    private static final String RSA_PRIVATE_KEY = "RSA_private_key.txt";
    private static final String DOC_ENCRYPTED = "doc_encrypted";
    private static final String DECRYPTED = "decrypted";
    private static final String FILE_PATH = PATH + "\\" + FILE_TO_ENCRYPT;
    private static final String RSA_PUBLIC_KEY_PATH = PATH + "\\" + RSA_PUBLIC_KEY;
    private static final String RSA_PRIVATE_KEY_PATH = PATH + "\\" + RSA_PRIVATE_KEY;
    
    protected void verifyEncryptedDocExist() throws FileNotFoundException, IOException {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        assertEquals(1, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifyDecryptedDocExist() throws FileNotFoundException, IOException {
        File dir = new File(PATH);
        File[] filesDecrypted = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(1, filesDecrypted.length);
        for(File file : filesDecrypted) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    protected void verifySuccessfullDecryptRSA() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException {
        //Encrypt
        RSACrypting.cryptingRSA(FILE_PATH, RSA_PUBLIC_KEY_PATH, 1);
        //Decrypt
        File dir = new File(PATH);
        File[] filesEncrypted = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED));
        RSACrypting.cryptingRSA(PATH + "\\" + filesEncrypted[0].getName(), RSA_PRIVATE_KEY_PATH, 2);
        File[] filesDecrypted = dir.listFiles((dir1, name) -> name.contains(DECRYPTED));
        assertEquals(1, filesDecrypted.length);
        for(File file : filesDecrypted) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
}
