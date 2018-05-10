# 	Computer Systems COMP30023 Project 2
#	name: Samuel Xu 
#   studentno: #835273
#	email: samuelx@student.unimelb.edu.au
#	login: samuelx
#
# 	Simple makefile for certcheck.c

all: certcheck.c
	gcc -g -Wall -o certcheck certcheck.c -lssl -lcrypto

clean: 
	$(RM) certcheck