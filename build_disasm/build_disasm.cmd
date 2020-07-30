@echo off

set build_type=%~1
set solution_dir=%~2
set msbuild_path=%~3
set configuration=%~4
set platform=%~5

echo Building Disasm

if exist "%msbuild_path%\MSBuild.exe" (
    set msbuild_exe="%msbuild_path%\MSBuild.exe"
) else (
    set msbuild_exe="%msbuild_path%\amd64\MSBuild.exe"
)

call %msbuild_exe% "%solution_dir%bddisasm\bddisasm.sln" /t:%build_type% /p:Configuration=%configuration% /p:Platform=%platform% /maxcpucount
IF %ERRORLEVEL% NEQ 0 goto build_failed


:done
echo "BUILD FINISHED"
exit /b 0

:build_failed
echo "ERROR: BUILD FAILED"
exit /b %ERRORLEVEL%
