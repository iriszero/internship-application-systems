CXX = gcc -g -o -Wall
all: ping

ping: ping.c
	gcc -g -o ping ping.c

clean:
	-rm ping
