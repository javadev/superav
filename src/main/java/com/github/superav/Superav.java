/*
 * $Id$
 *
 * Copyright 2015 Valentyn Kolesnikov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.superav;

import java.io.File;

public class Superav extends Findf {
    public static void main(String[] args) throws Exception {
        final Superav superav = new Superav();
        String startMes =
   "\n ----------------------------------------- \n"
 + "|  Super Antivirus for DOS16/WIN32/Java  ||\n"
 + "|         Version 1.0 build 023          ||  javadev75@gmail.com\n"
 + " ========================================= \n";

        printf(startMes);
        for (String arg : args) {
            if (arg.startsWith("/") || arg.startsWith("--")) {
                String pKey = arg.substring(arg.startsWith("--") ? 2 : 1);
                if (pKey.equals("*")) {
                    superav.flagAllFiles = true;
                    continue;
                }
                if (pKey.equalsIgnoreCase("r")) {
                    superav.flagSubdir = false;
                    continue;
                }
            }
        }
        if (args.length >= 1)  {
            for (String arg : args) {
                if (!arg.startsWith("/") && !arg.startsWith("--")) {
                    printf(String.format("\nProcessing %s\n", arg));
                    superav.scanPath(new File(arg), new Visitor() {
                        public void checkFile(File file) {
                            superav.checkFile(file);
                        }
                    });
                }
            }
        } else {
            printf("\nUsage: java -jar superav.jar Fname|Path /Keys\n"
                 + "    --*  scan all files\n"
                 + "    ---  disinfect\n"
                 + "    --E  delete infected files\n"
                 + "    --L  make virus list\n"
                 + "    --O  display OK messages\n"
                 + "    --R  do not scan subdirectories\n"
                 + "    --B  do not scan sectors (32-bit by default)\n"
                 + "    --M  do not scan memory (32-bit by default)\n"
                 + "    --V  enable redundant scanning\n"
                 + "    --W[=filename] save report\n"
                 + "    --Z  disable aborting\n"
                 + "    --P  save pages\n");
        }

    }

    public void checkFile(File file) {
        Log.info(file.getAbsolutePath() + "\tok.");
    }
}
