CC=gcc
CFLAGS=-s -lcrypto
# CFLAGS=-lcrypto -g -fsanitize=address,undefined -fstack-protector-strong -Wall -Wextra -pedantic

all: clean build

default: build

build: server.c client.c transport.c io.c security.c sec.c tlv.c
	${CC} -o server server.c transport.c io.c security.c sec.c tlv.c ${CFLAGS}
	${CC} -o client client.c transport.c io.c security.c sec.c tlv.c ${CFLAGS}

clean:
	rm -rf server client *.bin *.out *.dSYM *.zip

zip: clean
	rm -f project2.zip
	mkdir -p project
	cp server.c client.c transport.c io.c security.c sec.c tlv.c transport.h io.h consts.h security.h sec.h tlv.h Makefile project
	zip project2.zip project/*
	rm -rf project
