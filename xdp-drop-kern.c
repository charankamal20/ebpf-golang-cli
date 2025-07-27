#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>

#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port_map SEC(".maps");

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (data + TOTSZ > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    __u32 key = 0;
    __u16 *blocked_port = bpf_map_lookup_elem(&blocked_port_map, &key);

    if (blocked_port == NULL) {
        return XDP_PASS;
    }

    if (tcph->source == htons(*blocked_port) || tcph->dest == htons(*blocked_port)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
