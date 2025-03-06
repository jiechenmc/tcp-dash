//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm-generic/types.h>
#include <linux/dns_resolver.h>

#define bpf_htons(x) ((__be16)___constant_swab16((x)))
#define bpf_ntohs(x) ((__be16)___constant_swab16((x)))

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

// count_packets atomically increases a packet counter on every invocation.
SEC("xdp") 
int count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end; // end of data from context
    void *data = (void *)(long)ctx->data;         // start of data from context

    // Point to the start of the ethernet header within the data
    struct ethhdr *eth = data;

    // Verify that the ethernet header is within the bounds of the data
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }

    // Check if the ethernet frame contains an IP packet (ETH_P_IP is the IPv4 EtherType) converts host to network bytes order
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(*eth); // Point to the IP header after the ethernet header
    // Verify that the IP header is within the bounds of the data
    if ((void *)iph + sizeof(*iph) > data_end)
    {
        bpf_printk("XDP: IP header validation failed\n");
        return XDP_PASS;
    }

    // ALLOW ALL NON TCP PACKETS THROUGH
    if (iph->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }
    
    // TCP information
    struct tcphdr *tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);


    // 1.2.3.4
    //      byte4                   byte3                         byte2                     byte1
    // iph->saddr >> 24, (iph->saddr & 0x00FF0000) >> 16, (iph->saddr & 0xFF00) >> 8, iph->saddr & 0xFF

    if ((void *)(tcph + 1) > data_end)
    {
        return XDP_PASS;
    }


    // Do work with TCP packet
    bpf_printk("RECV FROM: <%pI4, %d, %pI4, %d>\n", &iph->saddr, bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));


    return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL";