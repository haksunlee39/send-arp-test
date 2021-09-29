
LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o src/arphdr.o src/ethhdr.o src/ip.o src/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
	rm -f send-arp-test src/*.o
