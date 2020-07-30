echo Generating the log gather tool...
pushd %cd%
cd %1\introcore\agents\windows\scripts
copy %1\bin\%2\%3\introgather_agent.exe gather.exe
call py -3 hexit.py gather.exe ../../../include/winagent_gather_%2.h gGatherAgent%2
del gather.exe
popd
echo Done!