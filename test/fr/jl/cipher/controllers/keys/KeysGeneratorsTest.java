/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.keys;

import fr.jl.cipher.controllers.crypting.CryptingException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 * Tests for keys generator
 */
public class KeysGeneratorsTest {
    
    private static final String PATH = "test\\fr\\jl\\cipher\\resources";    
    private static final String KEY = "key";
    private static final String PRIVATE_KEY = "private_key";
    private static final String PUBLIC_KEY = "public_key";
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    
    @After
    public void tearDown() {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(KEY) || name.startsWith(PRIVATE_KEY) || name.startsWith(PUBLIC_KEY));
        for(File file : files) {
            file.delete();
        }
    }

    @Test
    public void testSuccessfullGenerateAndSaveAESKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys(PATH, AES);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(KEY));
        assertEquals(1, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    @Test
    public void testSuccessfullGenerateAndSaveRSAKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys(PATH, RSA);
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(PRIVATE_KEY) || name.startsWith(PUBLIC_KEY));
        assertEquals(2, files.length);
        for(File file : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                assertNotNull(br.readLine());
            }
        }
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorGenerateAndSaveKeysWithNullPath() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys(null, AES);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorGenerateAndSaveKeysWithNotExistingPath() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys("FolderWhoNotExist", AES);
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorGenerateAndSaveKeysWithEmptyPath() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys("", AES);
    }
      
    @Test
    (expected=CryptingException.class)
    public void testErrorGenerateAndSaveKeysWithNullAlgorithm() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys(PATH, null);
    }
    
    @Test
    (expected=CryptingException.class)
    public void testErrorGenerateAndSaveWithNotExistingAlgorithm() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException{        
        KeysGenerators.generateAndSaveKeys(PATH, "algoNotExist");
    }
    
}
