.PHONY: all build link clean

CFLAGS := -m64 -Os -ffreestanding -fno-jump-tables -masm=intel -fPIE -fomit-frame-pointer -mgeneral-regs-only -march=nehalem -fno-stack-protector -Wall -Wextra -Wno-unused-parameter

SOURCE_FILES := $(wildcard *.c)
OBJECT_FILES := $(patsubst %.c,%.o,$(wildcard *.c))
BINARY_NAME := $(patsubst %.c, %, $(wildcard *.c))_content

%.o: %.cpp
	@gcc $(CFLAGS) -c $< -o $@

all: $(OBJECT_FILES) link
	@cat $(BINARY_NAME) > agents_content
	@xxd -i agents_content agents_content.h
	@sed -i agents_content.h -e 's/agents_content\[\]/gLixAgents[]/' agents_content.h

link:
	@ld -PIE $(OBJECT_FILES) -T linker.ld -o $(BINARY_NAME)

clean:
	@rm *.o $(BINARY_NAME) agents_content
