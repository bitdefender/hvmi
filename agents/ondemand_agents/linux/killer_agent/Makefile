PROG = killer_agent
OBJS = ../util.o main.o
CFLAGS = -std=c99 -O2 -g -Wall -pedantic -DDEBUG
LDFLAGS =

all: $(PROG)
	$(CC) $(CFLAGS) $(OBJS) -o $(PROG)
	strip $<

ifeq ($(MAKECMDGOALS),)
-include $(wildcard *.d)
endif

$(PROG): $(OBJS)

# Generate dependencies and compile.
%.o: %.c
	$(CC) -MM $^ $(CFLAGS) > $*.d
	$(CC) -o $@ -c $< $(CFLAGS)
%.o: %.d

clean:
	rm -f $(OBJS) *.d

cleanall: clean
	rm -f $(PROG)

.PHONY: all clean cleanall
