.PHONY: all build link clean

all: build link

CC=

INCLUDE_DIR := ../../../../../include/public/

CFLAGS := -m64 -Os -fverbose-asm -ffreestanding -fno-jump-tables -masm=intel -fPIE -fomit-frame-pointer -mgeneral-regs-only -march=nehalem -fno-stack-protector -Wall -Wextra -Wno-unused-parameter -I$(INCLUDE_DIR)

build:
	@gcc $(CFLAGS) -c handlers.c -S
	@gcc $(CFLAGS) -c trampolines.S -o handlers.o

link:
	@ld -PIE handlers.o -T linker.ld -o handlers
	@xxd -i handlers > detours_hypercall.h
	@sed -i detours_hypercall.h -e 's/handlers\[\]/gLixDetours[]/' detours_hypercall.h

clean:
	rm *.o handlers handlers.s
