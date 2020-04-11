#pragma once
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <queue>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>

/* 
 *Note that "buffer" should be at least the MTU size of the 
 * interface, eg 1500 bytes 
 */
#define MAX_LEN 1600
#define ROUTER_NUM_INTERFACES 4

#define DIE(condition, message) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[%d]: %s\n", __LINE__, (message)); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

typedef struct {
	int len;
	char payload[MAX_LEN];
	int interface;
} packet;

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

extern int interfaces[ROUTER_NUM_INTERFACES];

int send_packet(int interface, packet *m);
void update(struct iphdr *ip_hdr);
int get_packet(packet *m);
void change(struct ether_arp *arp, struct ether_arp *eth_arp);
char *get_interface_ip(int interface);
int get_interface_mac(int interface, uint8_t *mac);
void init();
void parse_arp_table();
uint16_t ip_checksum(void* vdata,size_t length);
void prepare_for_reply (struct ether_arp *eth_arp,std::queue<packet> *packets_to_transmit);
void prepare_for_request(struct ether_header *eth_hdr, struct ether_arp *eth_arp,struct ether_arp *arp, packet *m);
void prepare_for_ttl(struct ether_header *eth_hdr,struct icmphdr *icmp_hdr,struct iphdr *ip_hdr, packet *m);
void prepare_send(struct route_table_entry *e,packet *m,struct iphdr *ip_hdr,struct ether_header *eth_hdr);
void prepare_for_unreach(struct ether_header *eth_hdr,struct icmphdr *icmp_hdr,struct iphdr *ip_hdr, packet *m);
bool verify_checksum(struct iphdr *ip_hdr);
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

