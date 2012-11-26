CC = gcc
LIB = libheaptropy.so

all: $(LIB)

$(LIB): heaptropy.c
	$(CC) -g3 -O0 -Wall -pedantic -std=c99 -c -fPIC $^
	$(CC) heaptropy.o -g3 -O0 -Wall -pedantic -std=c99 -shared -ldl -lrt -o $@

test: $(LIB) test.c
	$(CC) test.c -g3 -O0 -o $@
	LD_PRELOAD=./$(LIB) ./test

clean:
	rm -f $(LIB) test *.o
