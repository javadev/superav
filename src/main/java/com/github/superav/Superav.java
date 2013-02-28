package com.github.superav;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Superav extends AbstractSuperav {
    public static void main(String[] args) throws Exception {
        Superav superav = new Superav();
        String startMes =
   "\n ----------------------------------------- \n"
 + "|  Super Antivirus for DOS16/WIN32/Java  ||\n"
 + "|         Version 1.0 build 023          ||  javadev75@gmail.com\n"
 + " ========================================= \n\n";

        Logger.getLogger(Superav.class.getName()).log(Level.INFO, startMes);
        for (String arg : args) {
            if (arg.startsWith("/") || arg.startsWith("-")) {
                String pKey = arg.substring(1);
                if (pKey.equals("*")) {
                    superav.flagAllFiles = true;
                    continue;
                }
            }
        }
    }
}
