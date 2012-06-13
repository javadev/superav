bin\BCC.EXE -IINCLUDE;src\main\c -ms -f- -d -vi- -wpro -weas -wpre -LLIB src/main/c/SILLYAV.C src/main/c/findf.c
bin\BCC.EXE -IINCLUDE;src\main\c -ms -f- -d -vi- -wpro -weas -wpre -LLIB src/main/c/sillyBAS.c src/main/c/sillylnk.c
bin\BCC.EXE -IINCLUDE;src\main\c -ms -f- -d -vi- -wpro -weas -wpre -LLIB src/main/c/sillytst.c
bin\MAKE.EXE /f SILLAV16.MAK

