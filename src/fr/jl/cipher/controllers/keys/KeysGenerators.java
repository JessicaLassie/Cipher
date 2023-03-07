/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.keys;

import fr.jl.cipher.controllers.common.Utils;
import fr.jl.cipher.controllers.crypting.CryptingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Class for the keys generation
 */
public class KeysGenerators {
    
    private static final String MANDATORY_OUTPUT_FOLDER = "output folder";
    private static final String MANDATORY_ALGORITHM = "algorithm";
    private static final String ALGORITHM_NOT_SUPPORTED = "Algorithm is not supported !";
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    
    private KeysGenerators() {
        throw new IllegalStateException("Utility class");
    }
    
    /**
     * Generate and save the keys
     * @param outputPath the path for save the keys
     * @param algorithm algorithm for the keys
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws CryptingException 
     */
    public static void generateAndSaveKeys(String outputPath, String algorithm) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException {
        Utils.checkMandatoryValue(outputPath, MANDATORY_OUTPUT_FOLDER);
        Utils.checkMandatoryValue(algorithm, MANDATORY_ALGORITHM);
        
        switch (algorithm) {
            case AES:
                    AESKeyGenerator.generateAndSaveAESKey(outputPath);
                break;
            case RSA:                
                    RSAKeysGenerators.generateAndSaveRSAKeys(outputPath);
                break;
            default :
                throw new CryptingException(ALGORITHM_NOT_SUPPORTED);
        }
    }
}
