package com.github.superav;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractSuperav {
    protected boolean flagAllFiles;

    public static void printf(String message) {
        Log.info(message);
    }
}
