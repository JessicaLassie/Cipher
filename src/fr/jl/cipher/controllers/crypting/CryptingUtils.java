/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.cipher.controllers.crypting;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Crypting utils
 */
public class CryptingUtils {
    
    private static final String DATE_FORMAT = "yyyyMMddHHmmss";
    
    private CryptingUtils() {
        throw new IllegalStateException("Utility class");
    }
        
    /**
     * Create format file
     * @param mode encrypt or decrypt mode
     * @param fileToCrypting the file to crypting
     * @return file for encrypt or decrypt output
     */
    protected static File preFormating(final int mode, final File fileToCrypting) {
        SimpleDateFormat formater = new SimpleDateFormat(DATE_FORMAT);
        final String date = formater.format(new Date());
        String path = fileToCrypting.getAbsolutePath();
        final int pos = path.indexOf('.');
        String modeType = "";
        switch (mode) {
            case 1:
                modeType = "_encrypted_";
                break;
            case 2:
                modeType = "_decrypted_";
                break;
            default :
                break;
        }
        return new File(path.substring(0, pos) + modeType + date + path.substring(pos, path.length()));
    }
    
}
