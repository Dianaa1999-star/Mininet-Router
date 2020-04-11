#include "skel.h"
#include <iostream>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <features.h>
#include <sys/types.h>
#include <algorithm>
#include <vector>
#include <queue>
#define MAX             700001
#define N               30
#define nm              150
#define ETHERTYPE_ARP	0x0806
#define	ETHERTYPE_IP	0x0800	
#define ICMP_ECHO		8
#define ARP_REQUEST		1 
#define ICMP_ECHOREPLY  0
#define ARPHRD_ETHER    1
#define ARP_REPLY       2 
#define SHA_SIZE        4
#define arp_hrd        ea_hdr.ar_hrd
#define arp_pro        ea_hdr.ar_pro
#define arp_hln        ea_hdr.ar_hln
#define arp_pln        ea_hdr.ar_pln
#define arp_op         ea_hdr.ar_op
using namespace std;

int interfaces[ROUTER_NUM_INTERFACES];


struct route_table_entry *rtable;
int rtable_size;
struct arp_entry *arp_table;
int arp_table_len;

struct	ether_arp {
	struct	arphdr ea_hdr;
	u_char	arp_sha[6];
	u_char	arp_spa[4];
	u_char	arp_tha[6];
	u_char	arp_tpa[4];
};
/*
	Cautarea binara cauta cea mai buna ruta in rtable.
*/
struct route_table_entry *get_best_route(__u32 dest_ip) {

int start,stop,m,result;
result = -1;
start = 0;
stop = rtable_size;
	while( start <= stop ) {
		m =( start + stop) / 2;
		switch ( rtable[m].prefix > (dest_ip & rtable[m].mask)) {
		case 1 : {
			stop = m - 1;
			break;
		} 
		case 0: {
			result = m;
			start = m + 1;
			break;
		}
	}
	}	
	if(result == -1){
		return NULL;
	}
    return &rtable[result];
}
/*
	Comparator care sorteaza in functie de prefix, respectiv masca.
*/
bool cmp(const route_table_entry& e1, const route_table_entry& e2){
	if(e1.prefix < e2.prefix){
		return true;
	} else if (e1.prefix == e2.prefix && e1.mask < e2.mask){
		return true;
	} else {
		return false;
	}
}
/*
	Functie care cauta in tabela arp, mac-ul potrivit ip-ului.
*/
struct arp_entry *get_arp_entry(__u32 ip) {
   int i = 0;
	while(i < arp_table_len) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
		++i;
	}

    return NULL;
}

/*
	Functie care parseaza tabela de rutare.
*/
int read_rtbl(struct route_table_entry *rtable) {
    FILE *f ;
    char buf[nm];
    f = fopen("rtable.txt", "r");
    DIE(f == NULL, "Couldn't open rtable.txt!\n");
    memset(buf, 0, sizeof(buf));
    int i = 0;
    for(; fgets(buf, sizeof(buf), f); i++){
        char my_prefix[N], my_next_hop[N], my_mask[N], my_interface[N];
        sscanf(buf, "%s %s %s %s", my_prefix, my_next_hop, my_mask, my_interface);
        rtable[i].prefix = inet_addr(my_prefix);
        rtable[i].mask = inet_addr(my_mask);
        rtable[i].next_hop = inet_addr(my_next_hop);
        rtable[i].interface = atoi(my_interface);
    }

   fclose(f);
   return i;
}
/*
	Functie in care setez tipul ARP_REPLY , interschimb datele, completez 
	campurile din structura si trimit pachetul.
*/
void prepare_for_request(struct ether_header *eth_hdr, struct ether_arp *eth_arp,struct ether_arp *arp, packet *m) {
	change(arp,eth_arp);
	memcpy(eth_hdr->ether_dhost,eth_hdr->ether_shost,sizeof(eth_hdr->ether_shost));
	memcpy(eth_arp->arp_tha,eth_arp->arp_sha,sizeof(eth_arp->arp_tha));
	int send_interface = m->interface;
	get_interface_mac(send_interface,eth_arp->arp_sha);
	eth_arp->arp_op = htons(ARP_REPLY);
	get_interface_mac(send_interface, eth_hdr->ether_shost);
	send_packet(m->interface,m);
}
/*
	Functie care interschimba datele din arp_tpa, implicit arp_spa.
*/
void change(struct ether_arp *arp, struct ether_arp *eth_arp) {
	memcpy(arp->arp_tpa,eth_arp->arp_tpa,sizeof(eth_arp->arp_tpa));
	memcpy(eth_arp->arp_tpa,eth_arp->arp_spa,sizeof(eth_arp->arp_tpa));
	memcpy(eth_arp->arp_spa,arp->arp_tpa,sizeof(arp->arp_tpa));

}
/*
	Functie care trimite un ARP REQUEST.
*/
void prepare_send(struct route_table_entry *e,packet *m,struct iphdr *ip_hdr,struct ether_header *eth_hdr) {
	// creez un pachet nou
	packet req;
	struct ether_header *eth_hd = (struct ether_header *)req.payload;
	struct ether_arp *eth_arp1 = (struct ether_arp *)(req.payload + sizeof(struct  ether_header));
	// setez campurile din eth_hd
	req.interface = e->interface;
	eth_hd->ether_type = htons (ETHERTYPE_ARP);
	get_interface_mac(req.interface, eth_hd->ether_shost);			
	hwaddr_aton("ff:ff:ff:ff:ff",eth_hd->ether_dhost);
	
	// completez campurile din struct arphdr ea_hdr;
	eth_arp1->arp_hrd = htons(ARPHRD_ETHER);
	eth_arp1->arp_pln = 4;
	eth_arp1->arp_hln = 6;
	eth_arp1->arp_pro = htons(ETHERTYPE_IP);
	eth_arp1->arp_op = htons(ARP_REQUEST);
	
	// setez restul campurilor
	memcpy(eth_arp1->arp_tpa,&e->next_hop,sizeof(e->next_hop));
	memcpy(eth_arp1->arp_spa,&ip_hdr->saddr,sizeof(ip_hdr->saddr));
	get_interface_mac(e->interface,eth_arp1->arp_sha);
	hwaddr_aton("00:00:00:00:00",eth_arp1->arp_tha);

	// calculez dimensiunea pachetului
	req.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	send_packet(req.interface,&req);
	int next_interface = e->interface;
	get_interface_mac(next_interface, eth_hdr->ether_shost);
	m->interface = next_interface;
}
/*
	Functie care updateaza tabela ARP; daca exista pachete
	ce trebuie dirijate catre acel router, le transmit acum. 
*/
void prepare_for_reply (struct ether_arp *eth_arp,std::queue<packet> *packets_to_transmit) {
	int dimen = sizeof(eth_arp->arp_spa);
	struct in_addr in;
	memcpy(&in,eth_arp->arp_spa,dimen);
	int dimen2 = sizeof(eth_arp->arp_sha);
	struct arp_entry ax;
	ax.ip = inet_addr(inet_ntoa(in));
	memcpy(ax.mac,eth_arp->arp_sha,dimen2);
	// updatez tabela ARP
	arp_table[arp_table_len] = ax;
	arp_table_len++;

	// cat timp mai sunt pachete de transmis trimit pachetul
	// si il scot din coada
	while (!packets_to_transmit->empty()) {
	struct ether_header *et = (struct ether_header *)packets_to_transmit->front().payload;
	get_interface_mac(packets_to_transmit->front().interface,et->ether_shost);
	memcpy(et->ether_dhost,eth_arp->arp_sha,SHA_SIZE);
	send_packet(packets_to_transmit->front().interface,&packets_to_transmit->front());
  	packets_to_transmit->pop();
 	}

}
int main(int argc, char *argv[]) {
	setvbuf ( stdout , NULL , _IONBF , 0) ;
	packet m;
	int rc;
	init();
	arp_table = new arp_entry[MAX];
	rtable = new route_table_entry[MAX];
	DIE(rtable == NULL, "mem");
	rtable_size = read_rtbl(rtable);
	std::queue<packet> packets_to_transmit;  
	arp_table_len = 0;
	sort(rtable,rtable + rtable_size,cmp);
while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		/*
		In functie de campul ether_header verific daca este un pachet IP.
		*/
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {	

		char *auxx = get_interface_ip(m.interface);
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
		/*
		Verific daca este un pachet destinat routerului si raspund doar daca
		este un pachet icmp de tip ECHO. Interschimb adresele , modific tipul 
		pachetului si il trimit.
		*/
		if (ip_hdr->daddr == inet_addr(auxx)) {
			if (icmp_hdr->type == ICMP_ECHO) {
				icmp_hdr->type = ICMP_ECHOREPLY;
				std::swap(ip_hdr->daddr, ip_hdr->saddr);  
				send_packet(m.interface, &m);
				continue;
			} else {
				continue;
			}
		}
		/*
			Verific checksum-ul daca este gresit, daca da, arunc pachetul.
		*/
		bool ver = verify_checksum(ip_hdr);
		if (ver == true) {
			continue;
		}
		/*
			Verific daca ttl-ul <= 1 si trimit un mesaj tip Time exceeded.
		*/
		if (ip_hdr->ttl <= 1) {
			prepare_for_ttl(eth_hdr, icmp_hdr, ip_hdr, &m);
			send_packet(m.interface, &m);
			continue;
		}
		/*
			Gasesc cea mai buna ruta pentru a trimite pachetul. Daca nu exista 
			ruta voi trimite un mesaj icmp de tipul Destination unreachable.
		*/
		struct route_table_entry *e = get_best_route(ip_hdr->daddr);
		if (e == NULL) {
			prepare_for_unreach(eth_hdr, icmp_hdr, ip_hdr, &m);
			send_packet(m.interface, &m);
			continue;
		}
		/*
			Decrementez TTL si updateaz checksum.
		*/
			update(ip_hdr);
			
			struct arp_entry *arp = get_arp_entry(e->next_hop);
		/*
			Adresa MAC nu este cunoscuta local si genereaz un ARP
			request, apoi transmit pe interfata destinatie. Salveaz pachetul 
			in coada pentru transmitere.
		*/
		 if (arp == NULL) {
			 prepare_send(e, &m, ip_hdr, eth_hdr);
			 packets_to_transmit.push(m);
			continue;
		 }
		 /*
			Trimit pachetul mai departe folosind functia send_packet.
		*/
			get_interface_mac(e->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost,&arp->mac,sizeof(arp->mac));
			send_packet(e->interface, &m);
}  
/*
	In functie de campul ether_header verific daca este un pachet ARP.
*/
	 if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
	 	packet pkg;
		struct ether_arp *eth_arp = (struct ether_arp *)(m.payload + sizeof(struct  ether_header));
		struct ether_arp *arp = (struct ether_arp *)(pkg.payload + sizeof(struct  ether_header));
		struct ether_header *eth_hdrr = (struct ether_header *)pkg.payload;
		/*
			Daca este un ARP_REQUEST ,apelez functia care trimite
			un pachet de tip ARP_REPLY cu adresa Mac potrivita.
		*/
		if (ntohs(eth_arp->arp_op) == ARP_REQUEST) {
			prepare_for_request(eth_hdr,eth_arp,arp,&m);
			continue;
		}
		/*
			Daca este un ARP_REPLY,apelez functia care updateaza tabela ARP;
			daca exista pachete ce trebuie dirijate catre acel router, le
			transmit acum. 
		*/
		if (ntohs(eth_arp->arp_op) == ARP_REPLY) {
			prepare_for_reply(eth_arp,&packets_to_transmit);
			
		}
			
}
}
}
