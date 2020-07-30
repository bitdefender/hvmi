@echo off

IF [%1] == [] goto missing_args

set configuration=%~1

echo Building HVMI for %configuration%

call msbuild.exe "hvmi.sln" /t:Build /p:Configuration=%configuration% /p:Platform=x64 /maxcpucount
IF %ERRORLEVEL% NEQ 0 goto build_failed

:done
echo "BUILD FINISHED"
exit /b 0

:build_failed
echo "ERROR: BUILD FAILED"
exit /b %ERRORLEVEL%

:missing_args
echo "Missing argument: build type"
echo "Usage: build Debug|Release"
exit /b 1
