@echo off
ml64 /Cp /c /nologo src\x64\sha3.asm
lib /nologo /out:lib\x64\sha3.lib sha3.obj
cl /c /nologo /O1 sha3_test.c 
link /machine:X64 /subsystem:console /LARGEADDRESSAWARE:NO sha3_test.obj lib\x64\sha3.lib
move sha3_test.exe bin\x64\
:del *.obj *.err