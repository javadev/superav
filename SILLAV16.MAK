.AUTODEPEND

#		*Translator Definitions*
CC = bcc +SILLAV16.CFG
TASM = TASM
TLIB = tlib
TLINK = tlink
LIBPATH = D:\BC31\LIB
INCLUDEPATH = D:\BC31\INCLUDE


#		*Implicit Rules*
.c.obj:
  $(CC) -c {$< }

.cpp.obj:
  $(CC) -c {$< }

#		*List Macros*


EXE_dependencies =  \
 sillyav.obj \
 findf.obj \
 sillybas.obj \
 sillylnk.obj \
 sillytst.obj

#		*Explicit Rules*
sillav16.com: sillav16.cfg $(EXE_dependencies)
  $(TLINK) /t/x/c/P-/L$(LIBPATH) @&&|
c0t.obj+
sillyav.obj+
findf.obj+
sillybas.obj+
sillylnk.obj+
sillytst.obj
sillav16
		# no map file
cs.lib
|


#		*Individual File Dependencies*
sillyav.obj: sillav16.cfg sillyav.c 

findf.obj: sillav16.cfg findf.c 

sillybas.obj: sillav16.cfg sillybas.c 

sillylnk.obj: sillav16.cfg sillylnk.c 

sillytst.obj: sillav16.cfg sillytst.c 

#		*Compiler Configuration File*
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


