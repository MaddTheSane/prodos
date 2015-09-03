all: prodos

prodos: prodos.o
	$(CC) -o $@ prodos.o

clean:
	rm -f prodos prodos.o
