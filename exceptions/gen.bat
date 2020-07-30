@echo off

py -3 .\exceptions.py jsons --build=2002 --verbose=2
if NOT %ERRORLEVEL% == 0 (
    exit /B %ERRORLEVEL%
)

del exceptions2.bin
rename exceptions.bin exceptions2.bin 