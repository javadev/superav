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
 + " ========================================= \n";

        printf(startMes);
        for (String arg : args) {
            if (arg.startsWith("/") || arg.startsWith("-")) {
                String pKey = arg.substring(1);
                if (pKey.equals("*")) {
                    superav.flagAllFiles = true;
                    continue;
                }
            }
        }
        if (args.length < 2)  {
            printf("\nUsage: java -jar superav.jar Fname|Path /Keys\n"
                 + "    /*  scan all files\n"
                 + "    /-  disinfect\n"
                 + "    /E  delete infected files\n"
                 + "    /L  make virus list\n"
                 + "    /O  display OK messages\n"
                 + "    /R  do not scan subdirectories\n"
                 + "    /B  do not scan sectors (32-bit by default)\n"
                 + "    /M  do not scan memory (32-bit by default)\n"
                 + "    /V  enable redundant scanning\n"
                 + "    /W[=filename] save report\n"
                 + "    /Z  disable aborting\n"
                 + "    /P  save pages\n");
        }
    }
}
