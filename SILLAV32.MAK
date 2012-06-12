.AUTODEPEND

#       *Translator Definitions*
CC = bcc32 +sillav32.CFG
TASM = TASM
TLIB = tlib
TLINK = ilink32
LIBPATH = C:\Users\valik\Documents\programs\BCC55\Lib
INCLUDEPATH = C:\Users\valik\Documents\programs\BCC55\Include


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
sillav32.com: sillav32.cfg $(EXE_dependencies)
  $(TLINK) /t/x/c/P-/L$(LIBPATH) @&&|
c0x32.obj+
sillyav.obj+
findf.obj+
sillybas.obj+
sillylnk.obj+
sillytst.obj
sillav32
        # no map file
cw32.lib+
import32.lib
|


#       *Individual File Dependencies*
sillyav.obj: sillav32.cfg src/main/c/sillyav.c 

findf.obj: sillav32.cfg src/main/c/findf.c 

sillybas.obj: sillav32.cfg src/main/c/sillybas.c 

sillylnk.obj: sillav32.cfg src/main/c/sillylnk.c 

sillytst.obj: sillav32.cfg src/main/c/sillytst.c 

#       *Compiler Configuration File*
sillav32.cfg: sillav32.mak
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
| sillav32.cfg


