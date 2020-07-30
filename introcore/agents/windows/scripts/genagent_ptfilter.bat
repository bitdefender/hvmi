echo Generating the PT filter...
pushd %cd%
cd %1\introcore\agents\windows\scripts
call nasm -f win64 ../agents/ptfilter64.asm
call link ../agents/ptfilter64.obj /ENTRY:_start /SUBSYSTEM:native
call py -3 hexit.py ptfilter64.exe ../../../include/winagent_ptdriver_%2.h gPtDriver%2
del ptfilter64.exe
del "../agents/ptfilter64.obj"
popd
echo Done!