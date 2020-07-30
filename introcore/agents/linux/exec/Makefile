.PHONY: all build link clean

CFLAGS := -m64 -Os -ffreestanding -fno-jump-tables -masm=intel -fPIE -fomit-frame-pointer -mgeneral-regs-only -march=nehalem -fno-stack-protector -Wall -Wextra -Wno-unused-parameter

SOURCE_FILES := $(wildcard *.c)
OBJECT_FILES := $(patsubst %.c,%.o,$(wildcard *.c))
BINARY_NAME := $(patsubst %.c, %, $(wildcard *.c))_content

%.o: %.cpp
	@gcc $(CFLAGS) -c $< -o $@

all: $(OBJECT_FILES) link
	@xxd -i $(BINARY_NAME) $(BINARY_NAME).h
	@sed -i $(BINARY_NAME).h -e 's/$(BINARY_NAME)\[\]/ gLixAgentExec[]/' $(BINARY_NAME).h


link:
	@ld -PIE $(OBJECT_FILES) -T linker.ld -o $(BINARY_NAME)

clean:
	@rm *.o $(BINARY_NAME)
