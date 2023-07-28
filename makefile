#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) quagmire3.c -o quagmire3

clean:
	rm quagmire3 *.o

