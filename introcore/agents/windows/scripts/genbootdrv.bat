echo Generating the boot driver...
pushd %cd%
cd %1\introcore\agents\windows\scripts
copy %1\bin\%2\%3\introbootdrv.sys remediation.sys
call py -3 hexit.py remediation.sys ../../../include/winbootdrv_%2.h gBootDriver%2
del remediation.sys
popd
echo Done!
