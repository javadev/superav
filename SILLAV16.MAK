.AUTODEPEND

#       *Translator Definitions*
CC = bin\bcc.exe +SILLAV16.CFG
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
 sillyav.obj \
 findf.obj \
 sillybas.obj \
 sillylnk.obj \
 sillytst.obj

#       *Explicit Rules*
sillav16.com: sillav16.cfg $(EXE_dependencies)
  $(TLINK) /t/x/c/P-/L$(LIBPATH) @&&|
LIB\c0t.obj+
sillyav.obj+
findf.obj+
sillybas.obj+
sillylnk.obj+
sillytst.obj
sillav16
        # no map file
cs.lib
|

#       *Individual File Dependencies*
sillyav.obj: sillav16.cfg src/main/c/sillyav.c 

findf.obj: sillav16.cfg src/main/c/findf.c 

sillybas.obj: sillav16.cfg src/main/c/sillybas.c 

sillylnk.obj: sillav16.cfg src/main/c/sillylnk.c 

sillytst.obj: sillav16.cfg src/main/c/sillytst.c 


#       *Compiler Configuration File*
sillav16.cfg: sillav16.mak
  copy &&|
-mt
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
| sillav16.cfg


