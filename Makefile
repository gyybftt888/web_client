CC = gcc
CFLAGS = -Wall

client_db:
	$(CC) $(CFLAGS) -o web_client web_client.c -lssl -lcrypto -libsqlite3
web_client:
	$(CC) $(CFLAGS) -o web_client web_client.c -lssl -lcrypto

clean:
	rm -f web_client