/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.common;

import fr.jl.cipher.controllers.crypting.CryptingException;

/**
 * Utils class
 */
public class Utils {
    
    /**
     * Check if the value is null or empty
     * @param propertyValue the value to check
     * @param propertyName the name of the value
     * @throws CryptingException 
     */
    public static void checkMandatoryValue(String propertyValue, String propertyName) throws CryptingException {
        if(propertyValue == null || propertyValue.equals("")) {
            throw new CryptingException(String.format("The %s is mandatory", propertyName));          
        }
    }
}
