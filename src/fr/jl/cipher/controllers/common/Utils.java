/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.common;

import fr.jl.cipher.controllers.crypting.CryptingException;
import java.io.File;

/**
 * Utils class
 */
public class Utils {
    
    private Utils() {
        throw new IllegalStateException("Utility class");
    }
    
    /**
     * Check if the value is null or empty
     * @param propertyValue the value to check
     * @param propertyName the name of the value
     * @throws CryptingException 
     */
    public static void checkMandatoryValue(final String propertyValue, final String propertyName) throws CryptingException {
        if(propertyValue == null || propertyValue.equals("")) {
            throw new CryptingException(String.format("The %s is mandatory", propertyName));          
        }
    }
    
    /**
     * Check if the file exist
     * @param pathFile the file path to check
     * @param propertyName the name of the value
     * @throws CryptingException 
     */
    public static void checkExistingFile(final String pathFile, final String propertyName) throws CryptingException {
        File file = new File(pathFile);
        if(!file.exists()) {
            throw new CryptingException(String.format("The %s not exist !", propertyName));  
        }
    }
}
