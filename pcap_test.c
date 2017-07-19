#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr *header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int res;
    struct ether_header *eth_hdr;
    struct ip           *ip_hdr;
    struct tcphdr       *tcp_hdr;
    char ip_src_buf[16];
    char ip_dst_buf[16];
    int data_len;
    char *data;
    int i, j;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
    {
        /* timeout */
        if(res == 0) {
            continue;
        }

        printf("**********************************\n");

        eth_hdr = (struct ether_header*) packet;

        printf("[mac addr]\n");
        printf("shost mac addr : %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_shost));
        printf("dhost mac addr : %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost));
        printf("\n");

        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
        {
            ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

            printf("[ip addr]\n");
            inet_ntop(AF_INET, &(ip_hdr->ip_src), ip_src_buf, sizeof(ip_src_buf));
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), ip_dst_buf, sizeof(ip_dst_buf));
            printf("shost ip addr : %s\n", ip_src_buf);
            printf("dhost ip addr : %s\n", ip_dst_buf);
            printf("\n");

            if(ip_hdr->ip_p == IPPROTO_TCP) // TCP protocol
            {
                tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                printf("[tcp port]\n");
                printf("source port : %d\n", ntohs(tcp_hdr->source));
                printf("dest port : %d\n", ntohs(tcp_hdr->dest));
                printf("\n");

                data = (char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                data_len = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                printf("[data]\n");
                write(1, data, (0x10<data_len?0x10:data_len));
                printf("\n");
            }
        }
        printf("**********************************\n\n");
    }
    /* And close the session */
    pcap_close(handle);
    return(0);
}