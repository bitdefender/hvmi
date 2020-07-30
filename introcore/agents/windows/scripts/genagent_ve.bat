echo Generating the #VE agent...
pushd %cd%
cd %1\introcore\agents\windows\scripts
copy %1\bin\%2\%3\introvecore.sys vecore.sys
call py -3 hexit.py vecore.sys ../../../include/winagent_ve_%2.h gVeDriver%2
del vecore.sys
popd
echo Done!