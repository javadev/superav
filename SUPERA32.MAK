.AUTODEPEND

#       *Translator Definitions*
CC = bcc32 +supera32.CFG
TASM = TASM
TLIB = tlib
TLINK = ilink32
LIBPATH = C:\Borland\BCC55\Lib
INCLUDEPATH = C:\Borland\BCC55\Include


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
supera32.exe: supera32.cfg $(EXE_dependencies)
  $(TLINK) /t/x/c/P-/L$(LIBPATH) @&&|
c0x32.obj+
superav.obj+
findf.obj+
superbas.obj+
superlnk.obj+
supertst.obj
supera32
        # no map file
cw32.lib+
import32.lib
|


#       *Individual File Dependencies*
superav.obj: supera32.cfg src/main/c/superav.c 

findf.obj: supera32.cfg src/main/c/findf.c 

superbas.obj: supera32.cfg src/main/c/superbas.c 

superlnk.obj: supera32.cfg src/main/c/superlnk.c 

supertst.obj: supera32.cfg src/main/c/supertst.c 

#       *Compiler Configuration File*
supera32.cfg: supera32.mak
  copy &&|
-f-
-Og
-d
-vi-
-wpro
-weas
-wpre
-DWIN32
-I$(INCLUDEPATH)
-L$(LIBPATH)
| supera32.cfg


