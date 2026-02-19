#
#   makefile
#

CC=gcc -Wall -O3 

# CC=gcc -Wall -lm -g -O0 

all:
	$(CC) utils.c parse.c dict.c transpositions.c perioc.c quagmire.c vigenere.c porta.c beaufort.c autokey.c polyalphabetic.c -o polyalphabetic
	cp polyalphabetic ..
	cp polyalphabetic ../quagmire
clean:
	rm polyalphabetic

