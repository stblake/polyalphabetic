#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) polyalphabetic.c -o polyalphabetic
	cp polyalphabetic quagmire
	$(CC) quagdict.c -o quagdict
clean:
	rm quagmire quagdict *.o

