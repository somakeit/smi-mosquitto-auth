NAME = smi_mosquitto_auth

CC = gcc
INC = -I ../mosquitto*/src/ -I ../mosquitto*/lib/ -I bcrypt/ -lcurl
CFLAGS = -std=c99 -fPIC -shared
OBJ = $(NAME).o bcrypt/bcrypt.a

all: $(OBJ) $(DEPS)
	$(CC) $(CFLAGS) -o $(NAME).so $(OBJ) $(INC)

%.o: %.c bcrypt/bcrypt.a
	$(CC) $(CFLAGS) -c -o $@ $< bcrypt/bcrypt.a $(INC)

bcrypt/bcrypt.a: bcrypt/*
	$(MAKE) CFLAGS='-fPIC' -C bcrypt

.PHONY: clean

clean:
	rm -f *.o *.so
	cd bcrypt && $(MAKE) clean
