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
