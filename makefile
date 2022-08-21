LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o get_my_addr.cpp
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
