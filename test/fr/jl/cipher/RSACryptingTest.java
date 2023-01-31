/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.CryptingException;
import java.io.File;
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
 * Tests for RSAEncryption
 */
public class RSACryptingTest extends AbstractEncryptionController {
       
    private static final String PATH = "test\\fr\\jl\\cipher\\resources";    
    private static final String DOC_ENCRYPTED = "doc_encrypted";
    private static final String DECRYPTED = "decrypted";
    
    @After
    public void tearDown() {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.contains(DECRYPTED));
        for(File file : files) {
            file.delete();
        }
    }
    
    @Test
    public void testSuccessfullEncryptRSA() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidAlgorithmParameterException{
        verifySuccessfullEncryptRSA();
    }
        
    @Test
    public void testSuccessfullDecryptRSA() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{
        verifySuccessfullDecryptRSA();
    }
    
    
}
