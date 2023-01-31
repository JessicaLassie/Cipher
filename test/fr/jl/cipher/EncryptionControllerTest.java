/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.CryptingException;
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
 *
 */
public class EncryptionControllerTest extends AbstractEncryptionController {
       
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
    public void testSuccessfullEncryptAES() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifySuccessfullEncryptAES();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorEncryptAESWithNullKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorEncryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorEncryptAESWithEmptyKey();
    }
    
    @Test
    (expected=IllegalArgumentException.class)
    public void testErrorEncryptAESWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorEncryptAESWithWrongKey();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorEncryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorEncryptAESWithNotExistingKey();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorEncryptAESWithNullFile();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorEncryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorEncryptAESWithNotExistingFile();
    }
    
    @Test
    public void testSuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{
        verifySuccessfullDecryptAES();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException{        
        verifyErrorDecryptAESWithNullKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException{        
        verifyErrorDecryptAESWithEmptyKey();
    }
    
    @Test
    (expected=IllegalArgumentException.class)
    public void testErrorDecryptAESWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException{        
        verifyErrorDecryptAESWithWrongKey();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorDecryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorDecryptAESWithNotExistingKey();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorDecryptAESWithNullFile();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorDecryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, InvalidAlgorithmParameterException{        
        verifyErrorDecryptAESWithNotExistingFile();
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
