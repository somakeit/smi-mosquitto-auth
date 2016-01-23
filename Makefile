NAME = smi_mosquitto_auth

CC = gcc
INC = -I ../mosquitto*/src/ -I ../mosquitto*/lib/ -I bcrypt/
CFLAGS = -std=c99 -fPIC -shared
OBJ = $(NAME).o bcrypt/bcrypt.a

all: $(OBJ) $(DEPS)
	$(CC) $(CFLAGS) $(INC) -o $(NAME).so $(OBJ)

%.o: %.c bcrypt/bcrypt.a
	$(CC) $(CFLAGS) $(INC) -c -o $@ $< bcrypt/bcrypt.a

bcrypt/bcrypt.a: bcrypt/*
	$(MAKE) CFLAGS='-fPIC' -C bcrypt

.PHONY: clean

clean:
	rm -f *.o *.so
	cd bcrypt && $(MAKE) clean
