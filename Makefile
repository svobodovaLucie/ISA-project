# File:          Makefile
# Institution:   FIT BUT
# Academic year: 2022/2023
# Course:        ISA - Network Applications and Network Administration
# Author:        Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz
#
# ISA project: Generator of NetFlow data from captured network traffic

CC=g++
CFLAGS=-Wall -Wextra -g -Werror
LFLAGS=-lpcap
EXEC=flow

all: $(EXEC)

$(EXEC): flow.o
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

flow.o: flow.cpp flow.h
	$(CC) $(CFLAGS) -c $< $(LFLAGS)

clean:
	rm $(EXEC) flow.o