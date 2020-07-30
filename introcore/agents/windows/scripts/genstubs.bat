call nasm -f bin -o agent32.bin ..\agents\agent32.asm
call py -3 hexit.py agent32.bin agent32.h gBootstrapAgentx86
call nasm -f bin -o agent64.bin ..\agents\agent64.asm
call py -3 hexit.py agent64.bin agent64.h gBootstrapAgentx64
call nasm -f bin -o trampoline64.bin ..\agents\trampoline64.asm
call py -3 hexit.py trampoline64.bin trampoline64.h gTrampolineAgentx64
call nasm -f bin -o trampoline32.bin ..\agents\trampoline32.asm
call py -3 hexit.py trampoline32.bin trampoline32.h gTrampolineAgentx86
del agent32.bin
del agent64.bin
del trampoline32.bin
del trampoline64.bin
