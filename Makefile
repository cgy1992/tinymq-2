all: tinymq send-msg
CC=gcc
CCFLAGS=-O3
INC=-I./.
LIB=-L./.

network.o: network.c
	$(CC) -c $(CCFLAGS) network.c

libnetwork: network.o
	ar rcs libnetwork.a network.o

server-main.o: server-main.c
	$(CC) $(INC) -c server-main.c $(CCFLAGS)

tinymq: server-main.o libnetwork
	$(CC) server-main.o $(LIB) -lnetwork -o tinymq

send-msg.o: send-msg.c libnetwork
	$(CC) $(INC) -c send-msg.c $(CCFLAGS)

send-msg: send-msg.o
	$(CC) send-msg.o $(LIB) -lnetwork -o send-msg

clean:
	rm -f *o
	rm -f send-msg
	rm -f tinymq
	rm -f libnetwork.a


 
