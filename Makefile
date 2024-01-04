all:
	gcc -L/home/ponsko/code/sqlite/.libs/ -g -fPIC -shared -I/home/ponsko/code/sqlite/ dolite.c -o dolite.so -Wall  -l:libsqlite3.so.0.8.6 -lsodium
