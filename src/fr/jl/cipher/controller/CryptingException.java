/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

/**
 *
 * @author Jessica LASSIE
 */
public class CryptingException extends Exception {
    
    private final String message;

    public CryptingException(String message) {
        this.message = message;
    }
    
    
    
}
