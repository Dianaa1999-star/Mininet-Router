#include "skel.h"
#include <iostream>
extern int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	int ret;
	ret = write(interfaces[sockfd], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	return 1;
}

void init()
{
	int s0 = get_sock("r-0");
	int s1 = get_sock("r-1");
	int s2 = get_sock("r-2");
	int s3 = get_sock("r-3");
	interfaces[0] = s0;
	interfaces[1] = s1;
	interfaces[2] = s2;
	interfaces[3] = s3;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}
/*
	Functie care calculeaza checksum.
*/
uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}
void prepare_for_ttl(struct ether_header *eth_hdr,struct icmphdr *icmp_hdr,struct iphdr *ip_hdr, packet *m) {
	packet aux;
	struct ether_header *eth_h = (struct ether_header *)aux.payload;
	struct iphdr *ip_h = (struct iphdr *)(aux.payload + sizeof(struct ether_header));
	
	memcpy(eth_h->ether_shost,eth_hdr->ether_dhost,sizeof(eth_hdr->ether_dhost));
	memcpy(eth_h->ether_dhost,eth_hdr->ether_shost,sizeof(eth_hdr->ether_shost));
	memcpy(eth_hdr->ether_shost, eth_h->ether_shost, sizeof(eth_h->ether_shost));
	memcpy(eth_hdr->ether_dhost, eth_h->ether_dhost, sizeof(eth_h->ether_dhost));
	/*
	Schimb sursa cu destinatia.
	*/
	std::swap(ip_hdr->daddr,ip_hdr->saddr);
	/*
	Initializez campul ip_hdr.
	*/
	ip_hdr->protocol = 1;
	ip_hdr->version = 4;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	/*
	Initializez campul icmp_hdr.
	*/
	icmp_hdr->type = 11;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = ip_checksum(icmp_hdr,sizeof(struct icmphdr));
	/*
	Setez dimensiunea pachetului.
	*/
	m->len = sizeof(struct ether_header) + sizeof(struct iphdr)
	+ sizeof(struct icmphdr) ;
}

void prepare_for_unreach(struct ether_header *eth_hdr,struct icmphdr *icmp_hdr,struct iphdr *ip_hdr, packet *m) {
	packet aux;
	struct ether_header *eth_h = (struct ether_header *)aux.payload;
	struct iphdr *ip_h = (struct iphdr *)(aux.payload + sizeof(struct ether_header));

	memcpy(eth_h->ether_shost,eth_hdr->ether_dhost,sizeof(eth_hdr->ether_dhost));
	memcpy(eth_h->ether_dhost,eth_hdr->ether_shost,sizeof(eth_hdr->ether_shost));
	memcpy(eth_hdr->ether_shost, eth_h->ether_shost, sizeof(eth_h->ether_shost));
	memcpy(eth_hdr->ether_dhost, eth_h->ether_dhost, sizeof(eth_h->ether_dhost));
	/*
	Schimb sursa cu destinatia.
	*/
	std::swap(ip_hdr->daddr,ip_hdr->saddr);
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->saddr = ip_h->saddr;
	/*
	Initializez campul ip_hdr.
	*/
	ip_hdr->protocol = 1;
	ip_hdr->version = 4;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
    /*
	Initializez campul icmp_hdr.
	*/
	icmp_hdr->type = 3;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = ip_checksum(icmp_hdr,sizeof(struct icmphdr));
	/*
	Setez dimensiunea pachetului.
	*/
	m->len = sizeof(struct ether_header) + sizeof(struct iphdr)
	+ sizeof(struct icmphdr) ;
}
/*
	Functie care decrementeaza ttl-ul si updateaza
	checksum-ul.
*/
void update(struct iphdr *ip_hdr) {
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
}
/*
	Functie care verifica ca este checksum-ul corect.
*/
bool verify_checksum(struct iphdr *ip_hdr) {
	uint16_t oldChecksum;
	oldChecksum = ip_hdr->check;
	ip_hdr->check = 0;
	if (oldChecksum != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
		return true;
	} else {
		return false;
	}
}