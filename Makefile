dns_example: dns_example.o sdns.o
	gcc -o dns_example dns_example.o sdns.o

dns_example.o: dns_example.c sdns.h
	gcc -c dns_example.c

sdns.o: sdns.c sdns.h
	gcc -c sdns.c

clean:
	rm dns_example dns_example.o sdns.o
