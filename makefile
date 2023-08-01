#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) quagmire.c -o quagmire

clean:
	rm quagmire *.o

