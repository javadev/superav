package com.github.superav;

import java.io.File;

public class Findf extends AbstractSuperav {
    public interface Visitor {
        void checkFile(File file);
    }
    public void scanPath(File dir, Visitor visitor) {
        File[] files = dir.listFiles();
        if (files == null) {
            Log.error("Can't read " + dir.getAbsolutePath());
            return;
        }
        for (final File file : files) {
            if  (Thread.currentThread().isInterrupted()) {
                return;
            }
            if (!file.isDirectory()) {
                visitor.checkFile(file);
            } else if (flagSubdir) {
                scanPath(file, visitor);
            }
        }
    }

}
