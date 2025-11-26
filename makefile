#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) polyalphabetic.c -o polyalphabetic
clean:
	rm polyalphabetic

