NAME = smi_mosquitto_auth

CC = gcc
INC = -I ../mosquitto*/src -I ../mosquitto*/lib
CFLAGS = -std=c99 -fPIC -shared
OBJ = $(NAME).o

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< $(INC)

all: $(OBJ)
	$(CC) $(CFLAGS) -o $(NAME).so $(OBJ) $(INC)

.PHONY: clean

clean:
	rm -f *.o *.so
