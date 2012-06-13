bin\BCC.EXE -IINCLUDE;src\main\c -ms -f- -d -vi- -wpro -weas -wpre -LLIB src/main/c/sillyav.c src/main/c/findf.c
bin\BCC.EXE -IINCLUDE;src\main\c -ms -f- -d -vi- -wpro -weas -wpre -LLIB src/main/c/sillybas.c src/main/c/sillylnk.c
bin\BCC.EXE -IINCLUDE;src\main\c -ms -f- -d -vi- -wpro -weas -wpre -LLIB src/main/c/sillytst.c
bin\MAKE.EXE /f SILLAV16.MAK
