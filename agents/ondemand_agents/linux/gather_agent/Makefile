PROG = gather_agent
OBJS = gather_agent.o ../util.o main.o
CFLAGS = -std=c99 -O2 -g -Wall -pedantic -DDEBUG
LDFLAGS =
REMOTE = int-boxa-centos

all: $(PROG)
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

scp:
	scp $(PROG) $(REMOTE):

.PHONY: all clean cleanall scp
