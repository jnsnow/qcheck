CFLAGS=-Wall -O2

all: qcheck
debug: CFLAGS += -ggdb -O0
debug: LDFLAGS += -ggdb -O0
debug: qcheck

qcheck: qcheck.o rbtree.o range.o pool.o

.PHONY: clean
clean:
	rm -f qcheck qcheck.o rbtree.o range.o pool.o *~
