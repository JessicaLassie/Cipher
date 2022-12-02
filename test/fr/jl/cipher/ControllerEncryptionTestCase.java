/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.CryptingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 */
public class ControllerEncryptionTestCase extends AbstractControllerEncryptionTestCase {
       
    private final static String PATH = "test\\fr\\jl\\cipher\\resources";    
    private final static String DOC_ENCRYPTED = "doc_encrypted";
    private final static String DECRYPTED = "decrypted";
    private final static String KEY = "key";
    private static final String PUBLIC_KEY = "public_key_";
    private static final String PRIVATE_KEY = "private_key_";
    
    @After
    public void tearDown() {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.startsWith(KEY) || name.contains(DECRYPTED) || name.startsWith(PUBLIC_KEY) || name.startsWith(PRIVATE_KEY));
        for(File file : files) {
            file.delete();
        }
    }

    @Test
    public void testSuccessfullEncryptAESWithoutKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifySuccessfullEncryptAESWithoutKey();
    }
    
    @Test
    public void testSuccessfullEncryptAESWithKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifySuccessfullEncryptAESWithKey();
    }
    
    @Test
    public void testSuccessfullEncryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifySuccessfullEncryptAESWithNullKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorEncryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithEmptyKey();
    }
    
    @Test
    public void testSuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{
        verifySuccessfullDecryptAES();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptAESWithNullKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{
        verifyErrorDecryptAESWithNullKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptAESWithEmptyFileKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException{        
        verifyErrorDecryptAESWithEmptyFileKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException{        
        verifyErrorDecryptAESWithEmptyKey();
    }
    
    @Test
    @Ignore
    public void testSuccessfullEncryptRSAWithoutKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException{
        verifySuccessfullEncryptRSAWithoutKey();
    }
    
    @Test
    @Ignore
    public void testSuccessfullEncryptRSAWithKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException{
        verifySuccessfullEncryptRSAWithKey();
    }
        
    @Test
    @Ignore
    public void testSuccessfullDecryptRSA() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{
        verifySuccessfullDecryptRSA();
    }
    
    
}
