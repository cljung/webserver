CC=gcc
CFLAGS=-I.
DEPS=
OBJ=webserver.o
USERID=123456789

all: webserver

webserver: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
	rm -rf *.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o webserver *.tar.gz

dist: tarball
tarball: clean
	tar -cvzf /tmp/$(USERID).tar.gz --exclude=./.vagrant . && mv /tmp/$(USERID).tar.gz .