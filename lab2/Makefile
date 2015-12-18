CC := gcc
CFLAGS := -Wall -ggdb
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c 
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: common.o client.o
	$(CC) $(LDFLAGS) -o client common.o client.o

server: common.o server.o
	$(CC) $(LDFLAGS) -o server common.o server.o


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o server.c

common.o: common.c
	$(CC) $(CFLAGS) -c -o common.o  common.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

