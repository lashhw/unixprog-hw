all: sandbox.so

sandbox.so: sandbox.c
	gcc -g -Wall -shared -o sandbox.so -fPIC sandbox.c -ldl

clean:
	rm sandbox.so
