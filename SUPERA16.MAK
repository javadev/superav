.AUTODEPEND

#       *Translator Definitions*
CC = bin\bcc.exe +SUPERA16.CFG
TASM = TASM
TLIB = tlib
TLINK = bin\tlink
LIBPATH = LIB
INCLUDEPATH = INCLUDE;src\main\c


#       *Implicit Rules*
.c.obj:
  $(CC) -c {$< }

.cpp.obj:
  $(CC) -c {$< }

#       *List Macros*

EXE_dependencies =  \
 superav.obj \
 findf.obj \
 superbas.obj \
 superlnk.obj \
 supertst.obj

#       *Explicit Rules*
SUPERA16.exe: SUPERA16.cfg $(EXE_dependencies)
  $(TLINK) /x/c/P-/L$(LIBPATH) @&&|
LIB\c0s.obj+
superav.obj+
findf.obj+
superbas.obj+
superlnk.obj+
supertst.obj
SUPERA16
        # no map file
cs.lib
|

#       *Individual File Dependencies*
superav.obj: SUPERA16.cfg src/main/c/superav.c 

findf.obj: SUPERA16.cfg src/main/c/findf.c 

superbas.obj: SUPERA16.cfg src/main/c/superbas.c 

superlnk.obj: SUPERA16.cfg src/main/c/superlnk.c 

supertst.obj: SUPERA16.cfg src/main/c/supertst.c 


#       *Compiler Configuration File*
SUPERA16.cfg: SUPERA16.mak
  copy &&|
-ms
-2
-f-
-Og
-d
-vi-
-wpro
-weas
-wpre
-I$(INCLUDEPATH)
-L$(LIBPATH)
| SUPERA16.cfg


