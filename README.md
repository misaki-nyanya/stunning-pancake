# stunning-pancake
## hahahaha

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
