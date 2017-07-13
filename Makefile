all: pcap_test
pcap_test: pcap_test.c
	gcc -o pcap_test pcap_test.c -lpcap
clean:
	rm pcap_test