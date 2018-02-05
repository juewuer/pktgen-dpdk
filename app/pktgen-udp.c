/*-
 * Copyright (c) <2010-2017>, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/* Created 2010 by Keith Wiles @ intel.com */

#include <cli_scrn.h>
#include "pktgen.h"

#include "pktgen-udp.h"

/**************************************************************************//**
 *
 * pktgen_udp_hdr_ctor - UDP header constructor routine.
 *
 * DESCRIPTION
 * Construct the UDP header in a packer buffer.
 *
 * RETURNS: next header location
 *
 * SEE ALSO:
 */

struct dnshdr {
	unsigned short int id;

	unsigned char rd:1;			/* recursion desired */
	unsigned char tc:1;			/* truncated message */
	unsigned char aa:1;			/* authoritive answer */
	unsigned char opcode:4;		/* purpose of message */
	unsigned char qr:1;			/* response flag */

	unsigned char rcode:4;		/* response code */
	unsigned char unused:2;		/* unused bits */
	unsigned char pr:1;			/* primary server required (non standard) */
	unsigned char ra:1;			/* recursion available */

	unsigned short int que_num;
	unsigned short int rep_num;
	unsigned short int num_rr;
	unsigned short int num_rrsup;
};

struct dnsdata{
	char query[32];
	unsigned short int type;
	unsigned short int class;
};

uint64_t xor_seed[2];
static inline uint64_t
xor_next(void){
	uint64_t s1 = xor_seed[0];
	const uint64_t s0 = xor_seed[1];
	xor_seed[0]=s0;
  	s1 ^= s1 << 23;                 /* a */ 
     	return ( xor_seed[ 1 ] = ( s1 ^ s0 ^ ( s1 >> 17 ) ^ ( s0 >> 26 ) ) ) +  s0;               /* b, c */ 
}

static __inline__ uint16_t 
pktgen_default_rnd_func(void) 
{ 
    return xor_next(); 
} 
#define DNS_URL_MAX_LEN 31
static char str[37] = "0123456789abcdefghijklmnopqrstuvwxyz";
static char dns_url[]="my.photo.ksyun.cn";
static int dns_url_len;
static char hostname[DNS_URL_MAX_LEN+1] = {9,'x','x','x','x','x','x','x','x','x',2,'k','6',4,'g','s','l','b',8,'k','s','y','u','n','c','d','n',3,'c','o','m',0};
static int hostname_len = 0;
static int pktgen_udp_inited = 0;
#define UDP_PORT_DNS 53
/*
return:
    0 - success
*/
int pktgen_udp_init(void)
{
    int d,h,hp;
    if(pktgen_udp_inited)
        return 0;
    dns_url_len = strlen(dns_url);
    hostname_len = dns_url_len+2;
    if(dns_url_len > DNS_URL_MAX_LEN)
        return 1;
    for(d=0,h=1,hp=0;d<=dns_url_len;d++,h++)
    {
        hostname[h]=dns_url[d];
        if(dns_url[d]=='.'||dns_url[d]=='\0')
        {
            hostname[hp]=h-hp-1;
            hp=h;
        }
    }
    
    pktgen_udp_inited = 1;
    return 0;
}

void *
pktgen_udp_hdr_ctor(pkt_seq_t *pkt, void *hdr, int type)
{
	uint16_t tlen;
	int i;
    
	if (type == ETHER_TYPE_IPv4) {
		udpip_t *uip = (udpip_t *)hdr;

		/* Zero out the header space */
		memset((char *)uip, 0, sizeof(udpip_t));
		
		if(pkt->dport == UDP_PORT_DNS)
		{
		    pktgen_udp_init();
			pkt->pktSize= pkt->ether_hdr_size+sizeof(udpip_t)+sizeof(struct dnshdr)+hostname_len+4;
		}		

		/* Create the UDP header */
		uip->ip.src         = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
		uip->ip.dst         = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
		tlen                = pkt->pktSize -
			(pkt->ether_hdr_size + sizeof(ipHdr_t));

		uip->ip.len         = htons(tlen);
		uip->ip.proto       = pkt->ipProto;

		uip->udp.len        = htons(tlen);
		uip->udp.sport      = htons(pkt->sport);
		uip->udp.dport      = htons(pkt->dport);

		if(pkt->dport == UDP_PORT_DNS)
		{
			struct dnshdr *dnsh = (struct dnshdr*)((char*)uip+sizeof(udpip_t));
			memset((char*)dnsh,0,sizeof(struct dnshdr));
			dnsh->id = htons(pktgen_default_rnd_func());
			dnsh->rd = 1;
			dnsh->que_num= htons(1);
		    unsigned char* dns_data=(unsigned char*)dnsh+sizeof(struct dnshdr);
			memcpy(dns_data, hostname, hostname_len);
			*((unsigned short int*)(dns_data+hostname_len)) = htons(1);  //type, 1 - type A
			*((unsigned short int*)(dns_data+hostname_len+2)) = htons(1); //class, 1 - IN

/*	
			struct dnsdata *dnsd = (struct dnsdata*)((char*)dnsh+sizeof(struct dnshdr));
	
			dnsd->query[0]=9;
			for(i = 1;i <10;i++)
			{
				dnsd->query[i]=str[pktgen_default_rnd_func()%36];
			}
			for(i = 10;i<32;i++)
			{
				dnsd->query[i] = hostname[i];
			}
			
			dnsd->type = htons(1);
			dnsd->class= htons(1);
			*/
	
		}	

		/* Includes the pseudo header information */
		tlen                = pkt->pktSize - pkt->ether_hdr_size;

		uip->udp.cksum      = cksum(uip, tlen, 0);
		if (uip->udp.cksum == 0)
			uip->udp.cksum = 0xFFFF;
	} else {
		uint32_t addr;
		udpipv6_t *uip = (udpipv6_t *)hdr;

		/* Zero out the header space */
		memset((char *)uip, 0, sizeof(udpipv6_t));

		/* Create the pseudo header and TCP information */
		addr                = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
		(void)rte_memcpy(&uip->ip.daddr[8], &addr,
				 sizeof(uint32_t));
		addr                = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
		(void)rte_memcpy(&uip->ip.saddr[8], &addr,
				 sizeof(uint32_t));

		tlen                = sizeof(udpHdr_t) +
			(pkt->pktSize - pkt->ether_hdr_size -
			 sizeof(ipv6Hdr_t) - sizeof(udpHdr_t));
		uip->ip.tcp_length  = htonl(tlen);
		uip->ip.next_header = pkt->ipProto;

		uip->udp.sport      = htons(pkt->sport);
		uip->udp.dport      = htons(pkt->dport);

		tlen                = sizeof(udpipv6_t) +
			(pkt->pktSize - pkt->ether_hdr_size -
			 sizeof(ipv6Hdr_t) - sizeof(udpHdr_t));
		uip->udp.cksum      = cksum(uip, tlen, 0);
		if (uip->udp.cksum == 0)
			uip->udp.cksum = 0xFFFF;
	}

	/* Return the original pointer for IP ctor */
	return hdr;
}
