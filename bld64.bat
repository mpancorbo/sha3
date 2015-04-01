@echo off
ml64 /Cp /c /nologo src\x64\md4.asm
lib /nologo /out:lib\x64\md4.lib md4.obj
cl /nologo /O1 md4_test.c lib\x64\md4.lib
move md4_test.exe bin\x64\
del *.obj *.err