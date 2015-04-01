@echo off
ml /coff /Cp /c /nologo src\x86\md4.asm
lib /nologo /out:lib\x86\md4.lib md4.obj
cl /nologo /O1 md4_test.c lib\x86\md4.lib
move md4_test.exe bin\x86\
del *.obj *.err