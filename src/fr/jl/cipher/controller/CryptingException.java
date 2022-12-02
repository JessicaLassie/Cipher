/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controller;

/**
 * Exception who can occurs during encryption or decryption
 */
public class CryptingException extends Exception {

    /**
     * Exception during encryption or decryption
     * @param message The detail message of exception
     */
    public CryptingException(final String message) {
        super(message);
    }
        
}
