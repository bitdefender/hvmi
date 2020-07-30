echo Generating the agent killer tool...
pushd %cd%
cd %1\introcore\agents\windows\scripts
copy %1\bin\%2\%3\introagentkiller_agent.exe killer.exe
call py -3 hexit.py killer.exe ../../../include/winagent_killer_%2.h gAgentKiller%2
del killer.exe
popd
echo Done!