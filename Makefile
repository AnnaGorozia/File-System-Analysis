filesys: FileSystem.c
	gcc -o $@ $^ -lpthread -lcrypto -lssl

