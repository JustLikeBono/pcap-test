#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "pcap-test.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: ./pcap-test <interface>\n");
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == 0){
        fprintf(stderr,"pcap_open_live(%s) return nullptr - %s\n",dev, errbuf);
        return -1;
    }
    
    while(1){
        
        sniff_one_packet(handle,errbuf);
        
    }
    return 0;
}