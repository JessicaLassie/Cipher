/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.CryptingException;
import java.io.File;
import java.io.FileNotFoundException;
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
public class EncryptionControllerTestCase extends AbstractEncryptionControllerTestCase {
       
    private final static String PATH = "test\\fr\\jl\\cipher\\resources";    
    private final static String DOC_ENCRYPTED = "doc_encrypted";
    private final static String DECRYPTED = "decrypted";
    private final static String KEY = "key";
    private final static String PUBLIC_KEY = "public_key_";
    private final static String PRIVATE_KEY = "private_key_";
    
    @After
    public void tearDown() {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(DOC_ENCRYPTED)|| name.startsWith(KEY) || name.contains(DECRYPTED) || name.startsWith(PUBLIC_KEY) || name.startsWith(PRIVATE_KEY));
        for(File file : files) {
            file.delete();
        }
    }
    
    @Test
    public void testSuccessfullEncryptAES() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifySuccessfullEncryptAES();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithNullKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorEncryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithEmptyKey();
    }
    
    @Test
    (expected=IllegalArgumentException.class)
    public void testErrorEncryptAESWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithWrongKey();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorEncryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithNotExistingKey();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorEncryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithNullFile();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorEncryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorEncryptAESWithNotExistingFile();
    }
    
    @Test
    public void testSuccessfullDecryptAES() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{
        verifySuccessfullDecryptAES();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptAESWithNullKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException{        
        verifyErrorDecryptAESWithNullKey();
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorDecryptAESWithEmptyKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException{        
        verifyErrorDecryptAESWithEmptyKey();
    }
    
    @Test
    (expected=IllegalArgumentException.class)
    public void testErrorDecryptAESWithWrongKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException, ClassNotFoundException, InvalidKeySpecException{        
        verifyErrorDecryptAESWithWrongKey();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorDecryptAESWithNotExistingKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorDecryptAESWithNotExistingKey();
    }
    
    @Test
    (expected=NullPointerException.class)
    public void testErrorDecryptAESWithNullFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorDecryptAESWithNullFile();
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorDecryptAESWithNotExistingFile() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CryptingException{        
        verifyErrorDecryptAESWithNotExistingFile();
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
