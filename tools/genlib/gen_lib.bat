@echo off

echo build lib from symbols %2 -> %3
set LIB=%1
%LIB% /def:%2 /out:%3 /machine:x86
