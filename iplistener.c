/* 
 * Author: Sathish Kumar R
 * Learn IPs from the network and capture it in table
 * use various capture methods
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <linux/ip.h> // IP header
#include <net/ethernet.h> // ETH_P_ALL

#define PFSOCKET  1
#define SOCKETRAW 2
#define PFSOCKET_MMAP  3
#define MAX_ENTRY 100
#define MAX_FRAMES 128

//#define RAW_DEBUG

/******************** IP Address Table - Learned from network ********************/
/* Each entry in the table */
typedef struct ipEntry {
    char *addr;
    struct ipEntry *next;
} ipEntry_t;

/* Hash based table */
ipEntry_t *ipTable[MAX_ENTRY];

/* Dump the full IP table */
void dumpIpTable() {
    ipEntry_t *next = NULL;
    int i;
    printf("Dumping IP Table\n");
    for (i = 0; i < MAX_ENTRY; i++) {
        next = ipTable[i];
        while(next) {
#ifdef RAW_DEBUG
            printf("Entry: %d - Addr: %s\n", i, next->addr);
#endif
            printf("%s, ", next->addr);
            next = next->next;
        }
    }
    printf("\n");
    return;
}

/* Just a ASCII based hash to place it in ipTable */
int getHash(char *addr) {
    int i;
    int hash = 0;
    
    for (i = 0; i < strlen(addr); i++) {
        hash = hash + 'a' - addr[i];
    }
    hash = hash % (MAX_ENTRY-1);
    return hash;
}

/* Add the learned entry. If duplicate ignore else add one */
void addEntry(char *addr) {
    int index;
    ipEntry_t *t = NULL;
    ipEntry_t *next;
    ipEntry_t *prev;
    
    index = getHash(addr);
#ifdef RAW_DEBUG
    printf("Hash for %s is %d\n", addr, index);
#endif
    if (!ipTable[index]) {
        ipTable[index] = (ipEntry_t*)malloc(sizeof(ipEntry_t));
        t = ipTable[index];
        t->next = NULL;
    } else {
        next = ipTable[index];
        while(next) {
            if (strcmp(next->addr, addr) == 0) {
#ifdef RAW_DEBUG
                printf("Duplicate entry - return\n");
#endif
                return;
            }
            prev = next;
            next = next->next;
        }
        prev->next = (ipEntry_t*)malloc(sizeof(ipEntry_t));
        t = prev->next;
        t->next = NULL;
    }
    
    if (t) {
#ifdef RAW_DEBUG
        printf("Adding data to ipTable\n");
#endif
        t->addr = (char*)malloc(strlen(addr)+1);
        strcpy(t->addr, addr);
    }
    return;
}

/******************** RAW Socket method ********************/
/* Listens for packets on network and learn IP */
void rawSocket(int proto) {
    int sockfd;
    char buffer[9000];
    void *buf = (void*)&buffer[0];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(struct sockaddr);
    int n;
    int max_count = 100;
    int count = 1;
    
    memset(buffer, 0, sizeof(buffer));
    
    sockfd = socket(AF_INET, SOCK_RAW, proto);
    if (sockfd < 0) {
        perror("socket");
        exit(-1);
    }
    
    printf("Learning IP Address from network\n");
    while(1) {
        n = recvfrom(sockfd, buf, sizeof(buffer), 0, (struct sockaddr*)&sender, &sender_len);
        if (n < 0)
            break;
#ifdef RAW_DEBUG
        printf("Family: %d, Port: %d, Address: %s\n", sender.sin_family, sender.sin_port, inet_ntoa(sender.sin_addr));
#endif
        addEntry(inet_ntoa(sender.sin_addr));
        count++;
        printf("%d\r", count);
        fflush(stdout);
        if (count > max_count) {
            printf("\n");
            break;
        }
    }
    
    if (count < max_count)
        perror("recvfrom:");
    
    dumpIpTable();
    
    return;
}

/******************** PF_SOCKET method ********************/

/* Parse ethernet frame and add entry to IP table */
void processEthernetFrame(char *buf) {
	/* Lets parse the buffer we received */
	struct ethhdr *eth;
	eth = (struct ethhdr*) buf;
	printf("Ethernet Info\n");
	printf("Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("Type: %.4x\n", ntohs(eth->h_proto));

	switch (ntohs(eth->h_proto)) {
		case ETH_P_IP:
			printf("Ethernet type: IP Proto\n");
			struct iphdr *ip;
			struct in_addr inet_addr;
			ip = (struct iphdr*) (buf + sizeof(struct ethhdr));
			printf("IP Info\n");
			inet_addr.s_addr = ip->saddr;
			printf("Source Address: %s\n", inet_ntoa(inet_addr));
    		addEntry(inet_ntoa(inet_addr));

			inet_addr.s_addr = ip->daddr;
			printf("Destination Address: %s\n", inet_ntoa(inet_addr));

			break;
		default:
			printf("Ethernet type: Non IP Proto\n");
			break;
	}
	dumpIpTable();
	return;
}

/*
 * PF_PACKET family. Bind to a device and eth type 
 * We can bind to a particular device.
 * We can listen to particular ethernet type packets
 * This function listens for the packet and adds to listener table
 */
void pfSocket(int proto) {
	int fd;
	char buffer[9000];
	struct sockaddr addr;
	int buflen;
	socklen_t addrlen = sizeof(addr);
	
	fd = socket(PF_PACKET, SOCK_RAW, proto);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	buflen = recvfrom(fd, buffer, sizeof(buffer), 0, &addr, &addrlen);
	if (buflen < 0) {
		perror("recvfrom");
		exit(-1);
	}

	printf("Packet received with len: %d\n", buflen);
	processEthernetFrame(buffer);

	return;
}

/******************** PF_SOCKET with MMAP method ********************/

#include <sys/ioctl.h>
#include <linux/if_packet.h> // sockaddr_ll
#include <net/if.h> // ifreq
#include <sys/mman.h> // mmap/munmap
#include <assert.h>
#include <poll.h>

void processRxRing(char *rx_ring, int fd) {
	struct tpacket_hdr *tpheader;
	int ret;
	static int rx_ring_offset = 0;

	tpheader = (struct tpacket_hdr*) (rx_ring + (rx_ring_offset * getpagesize()));
	
	while(1) {
#if 0
		char buffer[9000];
		struct sockaddr_in addr;
		int addrlen = sizeof(addr);
		printf("Lets wait in recv\n");
		ret = recvfrom(fd, buffer, 9000, 0, (struct sockaddr*)&addr, &addrlen);
#endif
		struct pollfd pollset;
		pollset.fd = fd;
		pollset.events = POLLIN | POLLERR | POLLRDNORM;
		pollset.revents = 0;
		ret = poll(&pollset, 1, 10000);
		if (ret < 0) {
			perror("poll");
		}
		printf("Poll event received: %d, POLLIN: %d\n", pollset.revents, POLLIN);

		if (tpheader->tp_status & TP_STATUS_USER) {
			printf("Got a packet to process\n");
			if (tpheader->tp_status & TP_STATUS_COPY) {
				printf("Incomplete packet\n");
			}
			if (tpheader->tp_status & TP_STATUS_LOSING) {
				printf("Packet dropped\n");
			}
			// Now process the packet
			processEthernetFrame(rx_ring + TPACKET_HDRLEN);
			tpheader->tp_status = 0;
			rx_ring_offset = (rx_ring_offset + 1) & (MAX_FRAMES - 1);
			tpheader = (struct tpacket_hdr*) (rx_ring + (rx_ring_offset * getpagesize()));
		}
	}
}

void pfSocketMmap(int proto) {
	int fd;
	int ret;
	int ifindex;
	int val;

	fd = socket(PF_PACKET, SOCK_RAW, proto);
	//fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

#if 0
	val = TPACKET_V2;
	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val))) {
		perror("setsockopt");
		exit(-1);
	}
#endif

	val = 4096 * 4096;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
	if (ret < 0) {
		perror("setsockopt");
		exit(-1);
	}
	

	/* Get interface index - used for binding interface */
	struct ifreq ifr;
	strncpy(ifr.ifr_name, "eth1", sizeof(ifr.ifr_name));
	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (ret < 0) {
		perror("ioctl");
		exit(-1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Interface index: %d, pagesize: %d\n", ifindex, getpagesize());

	/* Bind to particular interface */
	struct sockaddr_ll llayer;
	memset(&llayer, 0, sizeof(llayer));
	llayer.sll_family = PF_PACKET;
	llayer.sll_protocol = ETH_P_ALL;
	llayer.sll_ifindex = ifindex;
	ret = bind(fd, (struct sockaddr*)&llayer, sizeof(llayer));
	if (ret < 0) {
		perror("bind");
		exit(-1);
	}

	/* Now start the RX ring registration */
	struct tpacket_req tp_req;
	char *ring;

	memset(&tp_req, 0, sizeof(tp_req));
	tp_req.tp_frame_size = getpagesize();
	tp_req.tp_frame_nr = MAX_FRAMES;
	tp_req.tp_block_size = MAX_FRAMES * getpagesize();
	tp_req.tp_block_nr = 1;

	ret = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void*)&tp_req, sizeof(tp_req));
	if (ret < 0) {
		perror("setsockopt");
		exit(-1);
	}

	ring = mmap(0, tp_req.tp_block_size * tp_req.tp_block_nr, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED) {
		printf("Error during mapping memory\n");
		exit(-1);
	}

	printf("Ring is created: %p\n", ring);
	processRxRing(ring, fd);

	munmap(ring, tp_req.tp_block_size * tp_req.tp_block_nr);
	return;	
}

/******************** Utility to select method ********************/
void learnIpAddr(int type) {
	if (type == PFSOCKET) {
		pfSocket(htons(ETH_P_ALL));
	} else if (type == SOCKETRAW) {
    	rawSocket(IPPROTO_TCP);
	} else if (type == PFSOCKET_MMAP) {
		pfSocketMmap(htons(ETH_P_ALL));
	} else {
		printf("Unknown socket type\n");
	}
	return;
}

/* Dump the table */
void cHandler(int signum) {
	printf("Keyboard interrupt\n");
	dumpIpTable();
	exit(0);
}

int main() {
	signal(SIGINT, cHandler);
    //learnIpAddr(IPPROTO_TCP);
    //learnIpAddr(SOCKET_RAW);
    learnIpAddr(PFSOCKET_MMAP);

    return 0;
}
