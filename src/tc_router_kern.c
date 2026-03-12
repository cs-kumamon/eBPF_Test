#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>

struct route_entry {
    __u32 ifindex;
    __u8  dst_mac[ETH_ALEN];
    __u8  src_mac[ETH_ALEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);          /* IPv4 src in network byte order */
    __type(value, struct route_entry);
} route_map SEC(".maps");

static __always_inline int handle_ipv4(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return BPF_OK;

    __u32 key = iph->saddr;
    struct route_entry *rt = bpf_map_lookup_elem(&route_map, &key);
    if (!rt)
        return BPF_OK;

    if (skb->ifindex == rt->ifindex)
        return BPF_OK;

    if (iph->ttl <= 1)
        return BPF_DROP;

    /* Update L2 addresses */
    __builtin_memcpy(eth->h_dest, rt->dst_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, rt->src_mac, ETH_ALEN);

    /* Decrement TTL and fix checksum */
    __u16 old = ((__u16)iph->ttl << 8) | iph->protocol;
    __u16 new = ((__u16)(iph->ttl - 1) << 8) | iph->protocol;
    iph->ttl -= 1;
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old, new, sizeof(__u16));

    return bpf_redirect(rt->ifindex, 0);
}

SEC("classifier")
int tc_router(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return BPF_OK;

    if (eth->h_proto == __constant_htons(ETH_P_IP))
        return handle_ipv4(skb, eth, data_end);

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
