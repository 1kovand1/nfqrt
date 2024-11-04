#define QNUM 123
#define MARK1 0x10 // 00 -- default, 10 -- default routing, 11 -- alternative routing, 01 -- continue proccessing
#define MARK2 0x8 
#define __USE_MISC
#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "nfqrt.h"
#include <errno.h>
#include "uhash.h"

extern UHash_connHash* map, *set;

int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *)
{
    int id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if (ph)
        id = ntohl(ph->packet_id);
    unsigned char* data;
    int len = nfq_get_payload(nfad, &data);
    uint32_t mark = nfq_get_nfmark(nfad);
    struct pkt_buff* pktb = pktb_alloc(AF_INET, data, len, 0);

    struct iphdr* iph = nfq_ip_get_hdr(pktb);
    nfq_ip_set_transport_header(pktb, iph);

    struct tcphdr* tcp = nfq_tcp_get_hdr(pktb);

    if (tcp->syn)
    {
        struct connData cdata = {.dstIp = iph->daddr, .srcIp = iph->saddr, .srcPort = 0};
        if (uhset_remove_connHash(set, cdata, NULL))
            nfq_set_verdict2(qh, id, NF_REPEAT, mark | MARK1 | MARK2, len, data);
        else
            nfq_set_verdict2(qh, id, NF_ACCEPT, mark &~ MARK1 &~ MARK2, len, data);
    }
    else
    {
        char* payload = nfq_tcp_get_payload(tcp, pktb);
        int payloadSize = nfq_tcp_get_payload_len(tcp, pktb);
        if (payloadSize == 0)
        {
            nfq_set_verdict2(qh, id, NF_ACCEPT, mark & ~MARK1 & ~MARK2, len, data); // Handshake -- no-op
            printf("Handshake -- no-op\n");
        }
        else
        {
            struct connData cdata = {.dstIp = iph->daddr, .srcIp = iph->saddr, .srcPort = tcp->source};
            struct buffer _payload = {0,0,0};
            _payload = uhmap_get_connHash(map, cdata, _payload);
            if (!_payload.data)
            {
                _payload.data = malloc(4096);
                _payload.pos = 0;
                _payload.size = 4096;
            }
            while (_payload.pos + payloadSize >= _payload.size)
            {
                _payload.size *= 2;
                _payload.data = realloc(_payload.data, _payload.size);
            }
            memcpy(_payload.data + _payload.pos, payload, payloadSize);
            _payload.pos += payloadSize;
            uhmap_add_connHash(map, cdata, _payload, NULL);

            if (tcp->psh)
            {
                uhmap_remove_connHash(map, cdata, NULL, NULL);
                char const *sni;
                int snilen;
                if (_payload.data[0] == 0x16)
                    snilen = get_SNI(_payload.data, &sni, _payload.pos);
                else
                    snilen = 0;
                if (snilen > 0)
                {
                    mark |= MARK1;
                    if (strncmp(sni, "2ip.ru", snilen) == 0)
                    {
                        printf("%.*s\n", snilen, sni);
                        cdata.srcPort = 0;
                        uhset_insert_connHash(set, cdata, NULL);
                        nfq_set_verdict(qh, id, NF_DROP, len, data);
                        sendRST(iph, tcp);
                        printf("Sending RST\n");
                        //nfq_set_verdict2(qh, id, NF_REPEAT, mark | MARK2, len, data); // RESET
                    }
                    else
                    {
                        nfq_set_verdict2(qh, id, NF_REPEAT, mark &~ MARK2, len, data); // Default routing
                        printf("SNI not in list\n");
                    }
                }
                else if (snilen == 0)
                {
                    nfq_set_verdict2(qh, id, NF_REPEAT, mark | MARK1 &~ MARK2, len, data); // No SNI -- Default routing
                    printf("Couldn't find SNI\n");
                }

                free(_payload.data);
            }
            else
            {
                nfq_set_verdict(qh, id, NF_ACCEPT, len, data); // Continue processing
                printf("Continue processing\n");
            }
        }
    }

    pktb_free(pktb);
    return 0;
}

int get_SNI(char const *payload, char const** sni, int size)
{
    size_t start = 0x4c;
    if (start + 1 >= size)
        return 0;
    uint16_t len = ntohs(*(uint16_t*)(payload+start));
    start += len + 2;
    if (start + 1 >= size)
        return 0;
    len = *(uint8_t*)(payload+start);
    start += len + 1;
    if (start + 1 >= size)
        return 0;
    short extLen = ntohs(*(uint16_t*)(payload+start));
    start += 2;
    size_t extStart = start;
    
    while (start - extStart < extLen)
    {
        if (start + 1 >= size)
            return 0;
        uint16_t type = *(uint16_t*)(payload+start);
        if (type == 0x00)
        {
            start += 7;
            *sni = payload+start + 2;
            if (start + 2 >= size)
                return size - start - 8;
            return ntohs(*(uint16_t*)(payload+start));
        }
        else
        {
            if (start + 2 >= size)
                return 0;
            len = ntohs(*(uint16_t*)(payload+start+2));
            start += len + 4;
        }
    }

    return 0;
}

// int get_SNI2(char const *payload, char const** sni, int size, int start)
// {
//     int len;    
//     while (start < size)
//     {
//         uint16_t type = *(uint16_t*)(payload+start);
//         if (type == 0x00)
//         {
//             start += 7;
//             *sni = payload+start + 2;
//             if (start + 2 >= size)
//                 return size - start - 8;
//             return ntohs(*(uint16_t*)(payload+start));
//         }
//         else
//         {
//             if (start + 2 >= size)
//                 return size - start - 8;
//             len = ntohs(*(uint16_t*)(payload+start+2));
//             start += len + 4;
//         }
//     }
//     return 0;
// }

unsigned short checksum(const char *buf, unsigned size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

void sendRST(struct iphdr const *ip, struct tcphdr const *tcp)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = tcp->source;
    daddr.sin_addr.s_addr = ip->saddr;

    unsigned char buf[40] = {};
    struct iphdr* newIp = (struct iphdr*)buf;
    newIp->daddr = ip->saddr;
    newIp->saddr = ip->daddr;
    newIp->ttl = 64;
    newIp->version = 4;
    newIp->ihl = 5;
    newIp->id = 0;
    newIp->tos = 0;
    newIp->tot_len = 40;
    newIp->frag_off = htons(0x4000);
    newIp->protocol = 6;

    struct tcphdr* newTcp = (struct tcphdr*)(buf + sizeof(struct iphdr));
    newTcp->rst = 1;
    newTcp->source = tcp->dest;
    newTcp->dest = tcp->source;
    newTcp->seq = tcp->ack_seq;
    newTcp->ack_seq = 0;//tcp->seq;
    newTcp->doff = 5;

    struct pseudo_header psh;
    psh.source_address = newIp->saddr;
    psh.dest_address = newIp->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char* pseudogram = malloc(psize);
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), newTcp, sizeof(struct tcphdr));

    newTcp->check=checksum((const char*)pseudogram, psize);

    sendto(sock, buf, 40, 0, (struct sockaddr*)&daddr, sizeof(daddr));

    daddr.sin_addr.s_addr = ip->daddr;
    daddr.sin_port = tcp->dest;

    newIp->daddr = ip->daddr;
    newIp->saddr = ip->saddr;

    newTcp->source = tcp->source;
    newTcp->dest = tcp->dest;
    newTcp->seq = tcp->seq;
    newTcp->check = 0;

    psh.dest_address = newIp->daddr;
    psh.source_address = newIp->saddr;

    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), newTcp, sizeof(struct tcphdr));

    newTcp->check = checksum((const char*)pseudogram, psize);

    sendto(sock, buf, 40, 0, (struct sockaddr*)&daddr, sizeof(daddr));

    free(pseudogram);

    close(sock);
}