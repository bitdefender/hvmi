@echo off

setlocal
call :setESC
set error_file="doxy_err.log"

doxygen Doxygen/Doxyfile 2> %error_file%

FOR /F "usebackq" %%A IN ('%error_file%') DO set size=%%~zA

if %size% == 0 (
	echo %ESC%[101;42m                           %ESC%[0m
	echo %ESC%[101;42m Doxy generation SUCCEEDED %ESC%[0m
	echo %ESC%[101;42m                           %ESC%[0m
) ELSE (
	echo %ESC%[101;93m                                                  %ESC%[0m
	echo %ESC%[101;93m Doxy generation FAILED with the following errors %ESC%[0m
	echo %ESC%[101;93m                                                  %ESC%[0m
	more %error_file%
)

del %error_file%

:setESC
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set ESC=%%b
  exit /B 0
)

exit /B 0