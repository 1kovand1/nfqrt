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

UHash_connHash *map, *set;

int main(int, char**)
{
    struct nfq_handle* handle = init_libnfq(); 
    struct nfq_q_handle* qh = bind_queue(handle, QNUM);
    map = uhmap_alloc_connHash();
    set = uhset_alloc_connHash();

    int fd = nfq_fd(handle);

    char buf[2048];
    int size;
    while ((size = recv(fd, buf, sizeof(buf), 0)) != -1)
    {
        printf("A packet is recieved\n");
        nfq_handle_packet(handle, buf, size);
    }

    //destroy

    uhash_free_connHash(map);
    uhash_free_connHash(set);
    nfq_close(handle);
    return 0;
}
//iptables -A OUTPUT -p tcp --tcp-flags SYN,PSH,FIN,RST,ACK PSH,ACK --dport 443 -j NFQUEUE --queue-num 123 --queue-bypass


struct nfq_handle* init_libnfq()
{
    struct nfq_handle* handle = nfq_open(); 
    if (!handle)
    {
        fprintf(stderr, "Handle crating error");
        exit(-1);
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0) 
    {
        fprintf(stderr, "error during nfq_unbind_pf()");
        exit(-1);
    }

    if (nfq_bind_pf(handle, AF_INET) < 0) 
    {
        fprintf(stderr, "error during nfq_bind_pf()");
        exit(-1);
    }
    
    return handle;
}

struct nfq_q_handle* bind_queue(struct nfq_handle *handle, int qnum)
{
    struct nfq_q_handle* qh = nfq_create_queue(handle, qnum, &callback, NULL);
    
    if (!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()");
        exit(-1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) 
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    return qh;
}

