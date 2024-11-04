#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "uhash.h"


# include <sys/types.h>
# include <sys/socket.h>
# include <stdint.h>

typedef	uint32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr
  {
    __extension__ union
    {
      struct
      {
	uint16_t th_sport;	/* source port */
	uint16_t th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t th_x2:4;	/* (unused) */
	uint8_t th_off:4;	/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t th_off:4;	/* data offset */
	uint8_t th_x2:4;	/* (unused) */
# endif
	uint8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
	uint16_t th_win;	/* window */
	uint16_t th_sum;	/* checksum */
	uint16_t th_urp;	/* urgent pointer */
      };
      struct
      {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
      };
    };
};

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
  };


//Data in network order!
struct connData
{
    uint32_t dstIp;
    uint32_t srcIp;
    uint16_t srcPort;
};

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

struct buffer
{
    int size;
    int pos;
    char* data;
};

inline static uhash_uint connDataHashFunc(struct connData data)
{
    return uhash_int32_hash(data.dstIp + 3*data.srcIp + 5*data.srcPort);
}

inline static bool connDataEq(struct connData a, struct connData b)
{
    return a.dstIp == b.dstIp && a.srcIp == b.srcIp && a.srcPort == b.srcPort;
}

UHASH_INIT(connHash, struct connData, struct buffer, connDataHashFunc, connDataEq);

struct nfq_handle* init_libnfq();
struct nfq_q_handle* bind_queue(struct nfq_handle* handle, int qnum);
int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data);
int get_SNI(char const *payload, char const** sni, int size);
//int get_SNI2(char const *payload, char const** sni, int size, int start);
void sendRST(struct iphdr const*, struct tcphdr const*);

uint16_t ntohs(uint16_t);
uint16_t htons(uint16_t);
uint32_t htonl(uint32_t);
uint32_t ntohl(uint32_t);