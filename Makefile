all: pcap-test

pcap-test: pcap-test.o main.o
	g++ -o pcap-test pcap-test.o main.o -lpcap

main.o: pcap-test.h main.cpp

pcap-test.o: pcap-test.h pcap-test.cpp

clean:
	rm -f pcap-test
	rm -f *.o
