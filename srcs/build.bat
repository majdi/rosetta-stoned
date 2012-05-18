@echo off

if exist Rosetta.obj del Rosetta.obj
if exist Rosetta.exe del Rosetta.exe

c:\masm32\bin\ml /c /Cp /coff Rosetta.asm
c:\masm32\bin\link /SUBSYSTEM:WINDOWS Rosetta.obj

pause