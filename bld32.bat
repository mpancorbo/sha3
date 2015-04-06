@echo off
ml /coff /Cp /c /nologo src\x86\sha3.asm
lib /nologo /out:lib\x86\sha3.lib sha3.obj
cl /nologo /O1 sha3_test.c lib\x86\sha3.lib
move sha3_test.exe bin\x86\
del *.obj *.err