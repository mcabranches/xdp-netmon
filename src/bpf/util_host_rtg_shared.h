#ifndef UTIL_HOST_RTG_SHARED_H
#define UTIL_HOST_RTG_SHARED_H

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "../shared.h"

//This is needed to avoid table conflicts between the router and apps
//Populate this with routing section in main XDP entry point
struct bpf_map_def SEC("maps") rtg_ind_table_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

static __always_inline int test_gpv(struct xdp_md *ctx)
{
	struct custom_meta_desc *cm;
	void *data = (void *)(long)ctx->data + sizeof(*cm);
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)eth + sizeof(*eth) <= data_end) 
	{
		struct iphdr *ip = data + sizeof(*eth);

		if ((void *)ip + sizeof(*ip) <= data_end)
        {
			if (ip->protocol == 17)
			{
				struct udphdr *udp = (void *)ip + sizeof(*ip);
            	if ((void *)udp + sizeof(*udp) <= data_end)
            	{
					if (bpf_ntohs(udp->dest) == GPV_DST_PORT)
						return 1;
				}
			}
		}
	}
	return 0;
        	
}

static __always_inline int get_hkey_cm_app(const struct xdp_md* ctx, struct hkey_t *hkey) 
{
	struct custom_meta_desc *cm;
	void *data = (void *)(long)ctx->data + sizeof(*cm);
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	
	if ((void *)eth + sizeof(*eth) <= data_end) 
	{
		struct iphdr *ip = data + sizeof(*eth);
		if ((void *)ip + sizeof(*ip) <= data_end)
        {
			hkey->proto = ip->protocol;
			if (ip->protocol == 17)
        	{
				struct udphdr *udp = (void *)ip + sizeof(*ip);
            	if ((void *)udp + sizeof(*udp) <= data_end)
            	{
					if (bpf_ntohs(udp->dest) != GPV_DST_PORT)
					{
						hkey->is_gpv = 0;
						hkey->sport = bpf_ntohs(udp->source);
						hkey->dport = bpf_ntohs(udp->dest);
						hkey->saddr = bpf_ntohl(ip->saddr);
						hkey->daddr = bpf_ntohl(ip->daddr);
					}
					else //get hkey from gpv
					{
						struct gpv_pkt_t *gpv = (void *)udp + sizeof(*udp);
						if ((void *)gpv + sizeof(*gpv) <= data_end)
						{
							hkey->is_gpv = 0;
							hkey->proto = gpv->ip_proto;
							hkey->sport = gpv->tp_src;
							hkey->dport = gpv->tp_dst;
							hkey->saddr = gpv->ip_src;
							hkey->daddr = gpv->ip_dst;
						}
					}
				}
			}
			else if (ip->protocol == 6)
			{
				struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            	if ((void *)tcp + sizeof(*tcp) <= data_end)
            	{
					hkey->is_gpv = 0;
					hkey->sport = bpf_ntohs(tcp->source);
					hkey->dport = bpf_ntohs(tcp->dest);
					hkey->saddr = bpf_ntohl(ip->saddr);
					hkey->daddr = bpf_ntohl(ip->daddr);
				}
			}
		}
	}	
	return -1;
}

#endif