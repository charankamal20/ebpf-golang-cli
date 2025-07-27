#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

__attribute__((section("xdp"), used))
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

    if (tcph->source == htons(8080) || tcph->dest == htons(8080)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
