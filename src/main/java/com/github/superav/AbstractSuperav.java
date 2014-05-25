package com.github.superav;

public abstract class AbstractSuperav {
    protected boolean flagAllFiles;
    protected boolean flagSubdir = true;

    public static void printf(String message) {
        Log.info(message);
    }
}
