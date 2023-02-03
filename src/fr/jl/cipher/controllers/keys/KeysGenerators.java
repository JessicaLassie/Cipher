/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.keys;

import fr.jl.cipher.controllers.crypting.CryptingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 *
 */
public class KeysGenerators {
    
    private static final String MANDATORY_OUTPUT_FOLDER = "Output folder is mandatory !";
    private static final String MANDATORY_ALGORITHM = "Algorithm is mandatory !";
    private static final String ALGORITHM_NOT_SUPPORTED = "Algorithm is not supported !";
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    
    public static void generateAndSaveKeys(String outputPath, String algorithm) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CryptingException {
        Objects.requireNonNull(outputPath, MANDATORY_OUTPUT_FOLDER);
        Objects.requireNonNull(algorithm, MANDATORY_ALGORITHM);
        
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
