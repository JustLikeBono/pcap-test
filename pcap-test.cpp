#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "pcap-test.h"


void print_ip_addr(u_int32_t addr)
{
    int i;
    u_int8_t t_addr[4];
    memcpy(t_addr,&addr,sizeof(u_int32_t));

    printf("%d.%d.%d.%d\n",t_addr[0],t_addr[1],t_addr[2],t_addr[3]);

}
void print_mac_addr(u_int8_t *addr)
{
    int i;
    for(i=0;i<5;i++)
        printf("%X-",addr[i]);
    printf("%X",addr[5]);
}
void sniff_one_packet(pcap_t *handle,char *errbuf)
{
    u_char * ptr;
    struct pcap_pkthdr* header;
    const u_char* packet=0;
    struct libnet_ethernet_hdr eth;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;

    int i;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) return;
    if (res == -1 || res == -2) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        return;
    }

    ptr = (u_char *)packet;
    memcpy(&eth,ptr,sizeof(libnet_ethernet_hdr));
    
    printf("\nEthernet Src Mac: ");
    print_mac_addr(eth.ether_shost);

    printf("\nEthernet Dst Mac: ");
    print_mac_addr(eth.ether_dhost);
    printf("\n");

    ptr += sizeof(libnet_ethernet_hdr);
    memcpy(&ip,ptr,sizeof(libnet_ipv4_hdr));
    
    printf("IP Src Address: ");
    print_ip_addr(ip.ip_src.s_addr);
    printf("IP Dst Address: ");
    print_ip_addr(ip.ip_dst.s_addr);
    
    ptr += sizeof(libnet_ipv4_hdr);
    memcpy(&tcp,ptr,sizeof(libnet_tcp_hdr));

    printf("TCP Src Port: %d\n",tcp.th_sport);
    printf("TCP Dst Port: %d\n",tcp.th_dport);
    
    
    u_int8_t data[16] = {0,};
    int len;
    len = (header->caplen-(sizeof(libnet_tcp_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_ethernet_hdr)));
 

    if(len>16)
        len = 16;
    ptr += sizeof(libnet_tcp_hdr);
    memcpy(&data,ptr,len);

    printf("Data: ");
    for(i=0;i<16;i++)
        printf("%02X ",data[i]);
    printf("\n");
    
}


