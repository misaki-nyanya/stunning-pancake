/**
 *	AUTHER: RILLKE ZHOU
 *	CREATE: 2016.03.07
 *	ACKNOWLEDGEMENT:
 *		Thanks to Tim Carstens, who wrote http://www.tcpdump.org/pcap.html.
 *		Most of the code I wrote is based on his work.
 *	DISCRIPTION:
 *		Using libpcap to capture tcp and udp packages on a specific interface.
 *		We captured DomU packages in DOM0's xen-backend, specifically, vif1.0.
 *	LAST TEST: 
 *		Ubuntu 14.04LTS SMP kernel-3.13.0-24-generic
 *		gcc 4.8.2 (Ubuntu 4.8.2-19ubuntu1) 
 *		xen 4.4
 *	COMPILE:
 *		gcc pcap_zwq.c -lpcap -o pcap_zwq
 *	USAGE:
 *		Useage : pcap_zwq <net interface name> <libpcap filter rule> <path for log>
 *	KNOWN PROBLEMS:
 *		1. Though we can input filter rule, the package handler only handles tcp.
 *			(since tcp and udp shares the same field for data of ports, 
 *			I used tcp struct to handle udp packages)
 *		2. I handled the case when user sends Ctrl+C signal. 
 *			But the program may be killed in other case.
 *			And the resources may not be recycled.
 *
 */



#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap.h>

//#define BUFSIZ 4096 (already defined in pcap.h)

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/**
 * DO NOT use cpu ticks to count time. 
 * Because we don't know what happened before we receive pkgs in this program.
 */

//pcap
char*							filter_exp;	/* The filter expression */
struct 							bpf_program fp;		/* The compiled filter expression */
bpf_u_int32 					mask;		/* The netmask of our sniffing device */
bpf_u_int32 					net;		/* The IP of our sniffing device */
char*							dev;
char							errbuf[PCAP_ERRBUF_SIZE];
pcap_t*							handle;

//package
const struct sniff_ethernet*	ethernet; /* The ethernet header */
const struct sniff_ip*			ip; /* The IP header */
const struct sniff_tcp*			tcp; /* The TCP header */
u_int 							size_ip;
u_int 							size_tcp;

//logfile
FILE* 							pkglog = NULL;

//default little endian
int								little_endian=1;

void sig_handler(int sig)
{
	if(sig == SIGINT){
		printf("\n Ctrl^C pressed, bye!\n");
		pcap_close(handle);
		pcap_freecode(&fp);
		if (NULL != pkglog){
			if (0 != fflush(pkglog)){
				fprintf(stderr,"  WARNING : log flush failed ! \n");
			}			
			if (0 != fclose(pkglog)){
				fprintf(stderr,"  WARNING : log close failed ! \n");
			}			
		}
		exit(0);
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct in_addr *src_addr;
	const struct in_addr *dst_addr;
	char *print_src_addr;
	char *print_dst_addr;
	char src_port[2] = {0x00,0x00};
	char dst_port[2] = {0x00,0x00};
	char *p;
	
	printf("got_packet : length of packet %d\n", (int)header->len);	
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		fprintf(stderr," WARNING : Invalid IP header length: %u bytes\n\n", size_ip);
		return; // not a IP package...nothing to do...
	}
	
	src_addr = &(ip->ip_src);
	dst_addr = &(ip->ip_dst);
	
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		fprintf(stderr," WARNING : Invalid TCP header length: %u bytes\n\n", size_tcp);
		// we also receive udp packages, but use the tcp struct to get data
	}
	
	/**
	 * be aware inet_ntoa uses one public variable to store the result
	 * if called continuously the latter will overwrite the former
	 */
	
	if (little_endian){
		p=(char *)(&(tcp->th_sport));	
		src_port[0] = p[1];
		src_port[1] = p[0];
		
		p=(char *)(&(tcp->th_dport));	
		dst_port[0] = p[1];
		dst_port[1] = p[0];	
	}else{
		p=(char *)(&(tcp->th_sport));	
		src_port[0] = p[0];
		src_port[1] = p[1];
		
		p=(char *)(&(tcp->th_dport));	
		dst_port[0] = p[0];
		dst_port[1] = p[1];	
	}	
	
	printf("src: %s:%hu \n",inet_ntoa(*src_addr),*((int *)src_port));
	printf("dst: %s:%hu \n",inet_ntoa(*dst_addr),*((int *)dst_port));	
	printf("Recieved time: %ld.%ld\n", header->ts.tv_sec,header->ts.tv_usec); 
	printf("Recieved time: %s\n", ctime((const time_t *)&header->ts.tv_sec)); 
	
	/**
     * be aware inet_ntoa uses one public variable to store the result
	 * if called continuously the latter will overwrite the former
	 */
	fprintf(pkglog,"%s,",inet_ntoa(*src_addr));
	fprintf(pkglog,"%s,",inet_ntoa(*dst_addr));
	fprintf(pkglog,"%hu,%hu,%ld.%ld,%d\n",*((int *)src_port),
										  *((int *)dst_port),
										header->ts.tv_sec,header->ts.tv_usec,
										(int)header->len
			);
	
	/* uncomment this to see the detail of the packet	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);	
	printf("Number of bytes: %d\n", header->caplen);
	int i;
	for(i=0; i<header->len; ++i)
	{
		printf(" %02x", packet[i]);
		if( (i + 1) % 16 == 0 )
		{
		  printf("\n");
		}
	}*/

	printf("\n\n");
	
}

int main(int argc, char *argv[])
{
	char *dev;
	
	if (1 == argc){
		printf("Useage : pcap_zwq <net interface name> <rule> <path for log>\n");
		return 0;
	}
	
	if (1 < argc){
		dev = argv[1];
	}
	
	if (2 < argc){
		filter_exp = argv[2];
	}else{
		filter_exp = "(proto (\\tcp or \\udp)) and (not dst host 192.168.67.255) and (not ip broadcast) and (not ip multicast) and (not ip6 multicast)";
	}
	
	if (3 < argc){
		pkglog = fopen(argv[3], "a");
	}else{
		pkglog = fopen("pkg.log", "a");
	}
	
	if (NULL == pkglog){
		fprintf(stderr,"Can't open file pkg.log ! Bye!\n");
		return 0;
	}
	
	union test_endian{
		int		x;
		char	y;
	}test;
	test.x = 1;
	little_endian = (test.y == 1);
	printf("Little_endian flag : %d \n",little_endian);
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}
	
	printf("Aim on Device\t: %s\n", dev);
	printf("Applying Filter\t: %s\n", filter_exp);	
	
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Can't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	
	// set receive only
	pcap_setdirection(handle, PCAP_D_IN);
	
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Can't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Can't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	signal(SIGINT, sig_handler);
	
	pcap_loop(handle, -1, got_packet, NULL);
	
	pcap_close(handle);
	pcap_freecode(&fp);
	
	if (0 != fflush(pkglog)){
		fprintf(stderr,"  WARNING : log flush failed ! \n");
	}	
	if (0 != fclose(pkglog)){
		fprintf(stderr,"  WARNING : log close failed ! \n");
	}
	
	return(0);
}
