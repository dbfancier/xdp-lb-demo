//
// Created by niujinlin on 2022/2/16.
//

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "ethproto.h"

#define LOAD_BALANCER_IP 0x20011ac
#define BACKEND_1_IP 0x30011ac
#define BACKEND_2_IP 0x40011ac
#define CLIENT_IP 0x50011ac
#define LOAD_BALANCER_MAC_SUFFIX 0x02
#define BACKEND_1_MAC_SUFFIX 0x03
#define BACKEND_2_MAC_SUFFIX 0x04
#define CLIENT_MAC_SUFFIX 0x05

static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i=0; i<4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }

    return ~csum;
}

static __always_inline __u16 ipv4_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_proxy(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data; // let ether net header address point to data address
    if (data + sizeof(struct ethhdr) > data_end) { // validate the data
        return XDP_DROP;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr); // let ip header address point to data address and move size of ether header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_ICMP) { // forbid ICMP protocol
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP) { // we just proxy the steam whose protocol is TCP/IP
        return XDP_PASS;
    }

    // we just process packet whose source address in client ip or backend ip
    if (ip->saddr == CLIENT_IP) {
        ip->daddr = BACKEND_1_IP;
        eth->h_dest[5] = BACKEND_1_MAC_SUFFIX;

        if ((bpf_ktime_get_ns() & 0x01) == 0x01) {
            ip->daddr = BACKEND_2_IP;
            eth->h_dest[5] = BACKEND_2_MAC_SUFFIX;
        }
    } else if ((ip->saddr == BACKEND_1_IP) || (ip->saddr == BACKEND_2_IP)) {
        ip->daddr = CLIENT_IP;
        eth->h_dest[5] = CLIENT_MAC_SUFFIX;
    } else {
        return XDP_PASS;
    }

    ip->saddr = LOAD_BALANCER_IP;
    eth->h_source[5] = LOAD_BALANCER_MAC_SUFFIX;

    ip->check = ipv4_csum(ip);


    return XDP_TX;
}


