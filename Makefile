CC = gcc
CFLAGS += -I./include -O3 -Wall
depend = src/event.o src/misc.o src/tcp.o src/udp.o

all: libtunsocket.a

libtunsocket.a: $(depend)
	ar -r -s libtunsocket.a $(depend)

.PHONY: clean udp_test tcp_test
clean:
	-rm -f $(depend) libtunsocket.a udp_test tcp_test et_test

udp_test: clean libtunsocket.a
	$(CC) $(CFLAGS) -o udp_test test/udp_test.c libtunsocket.a

tcp_test: clean libtunsocket.a
	$(CC) $(CFLAGS) -o tcp_test test/tcp_test.c libtunsocket.a

et_test: clean libtunsocket.a
	$(CC) $(CFLAGS) -o et_test test/et_test.c libtunsocket.a
