@echo off

echo extracting export symbols %2 -> %3
echo LIBRARY %4 > %3
echo EXPORTS >> %3
set DUMPBIN=%1
for /f "skip=19 tokens=4" %%A in ('%DUMPBIN% /exports %2') do echo %%A >> %3

