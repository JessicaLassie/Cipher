/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher;

import fr.jl.cipher.controller.KeysController;
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
 *
 */
public class KeysControllerTestCase {
    
    private static final String PATH = "test\\fr\\jl\\cipher\\resources";    
    private static final String KEY = "key";
    private static final String PRIVATE_KEY = "private_key";
    private static final String PUBLIC_KEY = "public_key";
    
    @After
    public void tearDown() {
        File dir = new File(PATH);
        File[] files = dir.listFiles((dir1, name) -> name.startsWith(KEY) || name.startsWith(PRIVATE_KEY) || name.startsWith(PUBLIC_KEY));
        for(File file : files) {
            file.delete();
        }
    }

    @Test
    public void testSuccessfullGenerateAndSaveAESKey() throws NoSuchAlgorithmException, IOException{        
        KeysController.generateAndSaveAESKey(PATH);
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
    (expected=NullPointerException.class)
    public void testErrorGenerateAndSaveAESKeyWithNullPath() throws NoSuchAlgorithmException, IOException{        
        KeysController.generateAndSaveAESKey(null);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorGenerateAndSaveAESKeyWithNotExistingPath() throws NoSuchAlgorithmException, IOException{        
        KeysController.generateAndSaveAESKey("FolderWhoNotExist");
    }
    
    @Test
    public void testSuccessfullGenerateAndSaveRSAKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{        
        KeysController.generateAndSaveRSAKeys(PATH);
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
    (expected=NullPointerException.class)
    public void testErrorGenerateAndSaveRSAKeysWithNullPath() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{        
        KeysController.generateAndSaveRSAKeys(null);
    }
    
    @Test
    (expected=FileNotFoundException.class)
    public void testErrorGenerateAndSaveRSAKeysWithNotExistingPath() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException{        
        KeysController.generateAndSaveRSAKeys("FolderWhoNotExist");
    }
    
}
