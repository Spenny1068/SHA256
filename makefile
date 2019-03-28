#MAKEFILE FOR MULTIPLE FILES

# Use this for a program main.cpp which uses both sha256 and sha256 modules

# the compiler: gcc or g++
CC = g++

# compiler flags:
# -g    adds debugging information to the executable file
# -Wall turns on most, but not all, compiler warnings
CFLAGS = -std=c++17 -g -Wall 

# default target (typing 'make' will execute the command after run:)
default: run

# to create the executable file 'main' we need the object files
run: main.o sha256.o
	$(CC) $(CFLAGS) -o main main.o sha256.o; ./main

# create the object files from the source files

# create main.o
main.o: main.cpp sha256.h
	$(CC) $(CFLAGS) -c main.cpp

# create sha256.o
sha256.o: sha256.cpp sha256.h
	$(CC) $(CFLAGS) -c sha256.cpp

# run 'make clean' to remove the executable file and the .o files
clean: 
	$(RM) main *.o *~
